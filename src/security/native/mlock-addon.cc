#include <napi.h>
#include <sys/mman.h>
#include <cerrno>
#include <cstring>

namespace {

// Wrap a JS Buffer with mlock(2) so the underlying memory is pinned
// in physical RAM and excluded from core dumps. Linux only.
Napi::Value Mlock(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "mlock_addon: expected Buffer")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  auto buf = info[0].As<Napi::Buffer<uint8_t>>();
  size_t len = buf.ByteLength();
  void* data = buf.Data();

  if (len == 0) {
    return Napi::Number::New(env, 0);
  }

  int rc = mlock(data, len);
  if (rc != 0) {
    int err = errno;
    char err_msg[256];
    snprintf(err_msg, sizeof(err_msg),
             "mlock failed: errno=%d (%s)", err, strerror(err));
    Napi::Error::New(env, err_msg).ThrowAsJavaScriptException();
    return env.Null();
  }
  return Napi::Number::New(env, static_cast<double>(len));
}

// Reverse mlock(2) so the buffer is allowed to be swapped and
// included in core dumps again.
Napi::Value Munlock(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "mlock_addon: expected Buffer")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  auto buf = info[0].As<Napi::Buffer<uint8_t>>();
  size_t len = buf.ByteLength();
  void* data = buf.Data();

  if (len == 0) {
    return Napi::Number::New(env, 0);
  }

  int rc = munlock(data, len);
  if (rc != 0) {
    int err = errno;
    char err_msg[256];
    snprintf(err_msg, sizeof(err_msg),
             "munlock failed: errno=%d (%s)", err, strerror(err));
    Napi::Error::New(env, err_msg).ThrowAsJavaScriptException();
    return env.Null();
  }
  return Napi::Number::New(env, static_cast<double>(len));
}

}  // namespace

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("mlock", Napi::Function::New(env, Mlock));
  exports.Set("munlock", Napi::Function::New(env, Munlock));
  return exports;
}

NODE_API_MODULE(mlock_addon, Init)
