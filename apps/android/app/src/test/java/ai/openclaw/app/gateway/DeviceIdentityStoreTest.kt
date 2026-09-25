package ai.openclaw.app.gateway

import ai.openclaw.app.SecurePrefs
import android.content.Context
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.File
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class DeviceIdentityStoreTest {
  private val app get() = RuntimeEnvironment.getApplication()
  private val legacyFile get() = File(app.filesDir, "openclaw/identity/device.json")

  @Before
  fun setUp() {
    legacyFile.delete()
  }

  @After
  fun tearDown() {
    legacyFile.delete()
  }

  @Test
  fun retiresLegacyEd25519OnlyAfterMlDsaIdentityIsDurable() {
    val backing = newBackingPrefs()
    val prefs = SecurePrefs(app, securePrefsOverride = backing)
    legacyFile.parentFile?.mkdirs()
    legacyFile.writeText(legacyEd25519IdentityJson(), Charsets.UTF_8)

    val created = DeviceIdentityStore.withPrefs(app, prefs).loadOrCreate()

    assertFalse(legacyFile.exists())
    assertEquals(created, DeviceIdentityStore.withPrefs(app, prefs).loadOrCreate())
    assertEquals(
      1952,
      android.util.Base64
        .decode(created.publicKeyRawBase64, android.util.Base64.DEFAULT)
        .size,
    )
  }

  @Test
  fun preservesLegacyEd25519WhenMlDsaPersistenceFails() {
    val backing = newBackingPrefs()
    val prefs = SecurePrefs(app, securePrefsOverride = backing)
    legacyFile.parentFile?.mkdirs()
    val legacyJson = legacyEd25519IdentityJson()
    legacyFile.writeText(legacyJson, Charsets.UTF_8)
    val store = DeviceIdentityStore.withPrefs(app, prefs, identityWriter = { false })

    val failure = runCatching { store.loadOrCreate() }.exceptionOrNull()

    assertTrue(failure is IllegalStateException)
    assertTrue(legacyFile.exists())
    assertEquals(legacyJson, legacyFile.readText(Charsets.UTF_8))
    assertFalse(backing.contains("device.identity.mldsa65"))
  }

  @Test
  fun freshInstallPersistsIdentityOnlyInSecurePrefs() {
    val backing = newBackingPrefs()
    val prefs = SecurePrefs(app, securePrefsOverride = backing)

    val created = DeviceIdentityStore.withPrefs(app, prefs).loadOrCreate()

    assertFalse(legacyFile.exists())
    assertEquals(created, DeviceIdentityStore.withPrefs(app, prefs).loadOrCreate())
    assertEquals(
      1952,
      android.util.Base64
        .decode(created.publicKeyRawBase64, android.util.Base64.DEFAULT)
        .size,
    )
    assertEquals(
      4032,
      android.util.Base64
        .decode(created.privateKeyRawBase64, android.util.Base64.DEFAULT)
        .size,
    )
  }

  @Test
  fun signsAndSelfVerifiesWithGatewayCompatibleMlDsa65Sizes() {
    val store = DeviceIdentityStore.withPrefs(app, SecurePrefs(app, securePrefsOverride = newBackingPrefs()))
    val identity = store.loadOrCreate()
    val signature = store.signPayload("v3|android-ml-dsa", identity)

    assertNotNull(signature)
    assertEquals(3309, decodeBase64Url(requireNotNull(signature)).size)
    assertTrue(store.verifySelfSignature("v3|android-ml-dsa", signature, identity))
    assertFalse(store.verifySelfSignature("v3|tampered", signature, identity))
  }

  @Test
  fun ignoresRetiredEd25519PreferenceSlotAndCreatesNewMlDsaIdentity() {
    val backing = newBackingPrefs()
    val prefs = SecurePrefs(app, securePrefsOverride = backing)
    backing.edit().putString("device.identity", "{\"deviceId\":\"retired-ed25519\"}").commit()

    val identity = DeviceIdentityStore.withPrefs(app, prefs).loadOrCreate()

    assertNotEquals("retired-ed25519", identity.deviceId)
    assertEquals(
      1952,
      android.util.Base64
        .decode(identity.publicKeyRawBase64, android.util.Base64.DEFAULT)
        .size,
    )
  }

  @Test
  fun corruptedLegacyFileIsDeletedAndReplacedWithStableIdentity() {
    val backing = newBackingPrefs()
    val prefs = SecurePrefs(app, securePrefsOverride = backing)
    legacyFile.parentFile?.mkdirs()
    legacyFile.writeText("{not-json", Charsets.UTF_8)

    val regenerated = DeviceIdentityStore.withPrefs(app, prefs).loadOrCreate()

    assertFalse(legacyFile.exists())
    assertEquals(regenerated, DeviceIdentityStore.withPrefs(app, prefs).loadOrCreate())
  }

  private fun newBackingPrefs() =
    app.getSharedPreferences(
      "device-identity-test-${UUID.randomUUID()}",
      Context.MODE_PRIVATE,
    )

  private fun decodeBase64Url(value: String): ByteArray {
    val normalized = value.replace('-', '+').replace('_', '/')
    val padded = normalized + "=".repeat((4 - normalized.length % 4) % 4)
    return android.util.Base64.decode(padded, android.util.Base64.DEFAULT)
  }

  private fun legacyEd25519IdentityJson(): String {
    val generator =
      org.bouncycastle.crypto.generators
        .Ed25519KeyPairGenerator()
    generator.init(
      org.bouncycastle.crypto.params
        .Ed25519KeyGenerationParameters(java.security.SecureRandom()),
    )
    val pair = generator.generateKeyPair()
    val publicKey = pair.public as org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
    val privateKey = pair.private as org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
    val privateKeyPkcs8 =
      org.bouncycastle.crypto.util.PrivateKeyInfoFactory
        .createPrivateKeyInfo(privateKey)
        .encoded
    return """{"deviceId":"retired-ed25519","publicKeyRawBase64":"${
      android.util.Base64.encodeToString(publicKey.encoded, android.util.Base64.NO_WRAP)
    }","privateKeyPkcs8Base64":"${
      android.util.Base64.encodeToString(privateKeyPkcs8, android.util.Base64.NO_WRAP)
    }","createdAtMs":1700000000000}"""
  }
}
