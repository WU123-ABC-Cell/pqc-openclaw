#include <napi.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <new>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace {

constexpr size_t kMaxSecureAllocationBytes = 1024 * 1024;

struct SecureAllocation {
  size_t length;
};

void SecureZero(void* data, size_t length) {
#ifdef _WIN32
  SecureZeroMemory(data, length);
#else
  volatile unsigned char* cursor =
      static_cast<volatile unsigned char*>(data);
  while (length-- > 0) {
    *cursor++ = 0;
  }
#endif
}

bool LockMemory(void* data, size_t length) {
#ifdef _WIN32
  return VirtualLock(data, length) != 0;
#else
  return mlock(data, length) == 0;
#endif
}

bool UnlockMemory(void* data, size_t length) {
#ifdef _WIN32
  return VirtualUnlock(data, length) != 0;
#else
  return munlock(data, length) == 0;
#endif
}

void ThrowLastMemoryError(Napi::Env env, const char* operation) {
  char message[256];
#ifdef _WIN32
  const unsigned long error = GetLastError();
  std::snprintf(message, sizeof(message), "%s failed: win32=%lu", operation,
                error);
#else
  const int error = errno;
  std::snprintf(message, sizeof(message), "%s failed: errno=%d (%s)",
                operation, error, std::strerror(error));
#endif
  Napi::Error::New(env, message).ThrowAsJavaScriptException();
}

Napi::Value Mlock(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "mlock_addon: expected Buffer")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  auto buffer = info[0].As<Napi::Buffer<uint8_t>>();
  if (buffer.ByteLength() == 0) {
    return Napi::Number::New(env, 0);
  }
  if (!LockMemory(buffer.Data(), buffer.ByteLength())) {
    ThrowLastMemoryError(env, "memory lock");
    return env.Null();
  }
  return Napi::Number::New(env, static_cast<double>(buffer.ByteLength()));
}

Napi::Value Munlock(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "mlock_addon: expected Buffer")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  auto buffer = info[0].As<Napi::Buffer<uint8_t>>();
  if (buffer.ByteLength() == 0) {
    return Napi::Number::New(env, 0);
  }
  if (!UnlockMemory(buffer.Data(), buffer.ByteLength())) {
    ThrowLastMemoryError(env, "memory unlock");
    return env.Null();
  }
  return Napi::Number::New(env, static_cast<double>(buffer.ByteLength()));
}

void FinalizeSecureBuffer(Napi::Env, uint8_t* data,
                          SecureAllocation* allocation) {
  if (data != nullptr && allocation != nullptr) {
    SecureZero(data, allocation->length);
    UnlockMemory(data, allocation->length);
#ifdef _WIN32
    VirtualFree(data, 0, MEM_RELEASE);
#else
    munmap(data, allocation->length);
#endif
  }
  delete allocation;
}

Napi::Value SecureCopy(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "mlock_addon: expected Buffer")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  auto source = info[0].As<Napi::Buffer<uint8_t>>();
  const size_t length = source.ByteLength();
  if (length == 0) {
    return Napi::Buffer<uint8_t>::New(env, 0);
  }
  if (length > kMaxSecureAllocationBytes) {
    Napi::RangeError::New(env,
                          "mlock_addon: secure allocation exceeds 1 MiB limit")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  void* allocation = nullptr;
#ifdef _WIN32
  allocation = VirtualAlloc(nullptr, length, MEM_COMMIT | MEM_RESERVE,
                            PAGE_READWRITE);
  if (allocation == nullptr) {
    ThrowLastMemoryError(env, "VirtualAlloc");
    return env.Null();
  }
#else
  allocation = mmap(nullptr, length, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (allocation == MAP_FAILED) {
    ThrowLastMemoryError(env, "mmap");
    return env.Null();
  }
#endif

  if (!LockMemory(allocation, length)) {
    ThrowLastMemoryError(env, "memory lock");
    SecureZero(allocation, length);
#ifdef _WIN32
    VirtualFree(allocation, 0, MEM_RELEASE);
#else
    munmap(allocation, length);
#endif
    return env.Null();
  }

#if !defined(_WIN32) && defined(MADV_DONTDUMP)
  if (madvise(allocation, length, MADV_DONTDUMP) != 0) {
    ThrowLastMemoryError(env, "madvise(MADV_DONTDUMP)");
    SecureZero(allocation, length);
    UnlockMemory(allocation, length);
    munmap(allocation, length);
    return env.Null();
  }
#endif

  auto* metadata = new (std::nothrow) SecureAllocation{length};
  if (metadata == nullptr) {
    SecureZero(allocation, length);
    UnlockMemory(allocation, length);
#ifdef _WIN32
    VirtualFree(allocation, 0, MEM_RELEASE);
#else
    munmap(allocation, length);
#endif
    Napi::Error::New(env, "mlock_addon: secure allocation metadata failed")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  std::memcpy(allocation, source.Data(), length);
  auto result = Napi::Buffer<uint8_t>::New(
      env, static_cast<uint8_t*>(allocation), length, FinalizeSecureBuffer,
      metadata);
  if (result.IsEmpty()) {
    // node-addon-api cannot attach our finalizer when external-Buffer
    // registration fails. Ownership has not transferred, so clean up here.
    FinalizeSecureBuffer(env, static_cast<uint8_t*>(allocation), metadata);
    return env.Null();
  }
  return result;
}

Napi::Value SecureMemzero(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "mlock_addon: expected Buffer")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  auto buffer = info[0].As<Napi::Buffer<uint8_t>>();
  SecureZero(buffer.Data(), buffer.ByteLength());
  return Napi::Number::New(env, static_cast<double>(buffer.ByteLength()));
}

}  // namespace

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("mlock", Napi::Function::New(env, Mlock));
  exports.Set("munlock", Napi::Function::New(env, Munlock));
  exports.Set("secureCopy", Napi::Function::New(env, SecureCopy));
  exports.Set("secureMemzero", Napi::Function::New(env, SecureMemzero));
  return exports;
}

NODE_API_MODULE(mlock_addon, Init)
