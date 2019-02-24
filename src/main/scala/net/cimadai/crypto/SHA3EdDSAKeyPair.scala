package net.cimadai.crypto

/**
  * Copyright Daisuke SHIMADA, Richard Gomes -  All Rights Reserved.
  * https://github.com/cimadai/iroha-scala
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at
  *      http://www.apache.org/licenses/LICENSE-2.0
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */

trait SHA3EdDSAKeyPair {
  val publicKey: SHA3EdDSAPublicKey
  val privateKey: SHA3EdDSAPrivateKey

  import scala.util.Try

  def sign(message: Array[Byte]): Try[Array[Byte]] = Try {
    SHA3EdDSAKeyPair.engine.initSign(privateKey.self)
    SHA3EdDSAKeyPair.engine.signOneShot(message)
  }

  def verify(signature: Array[Byte], message: Array[Byte]): Try[Boolean] = Try {
    SHA3EdDSAKeyPair.engine.initVerify(publicKey.self)
    SHA3EdDSAKeyPair.engine.verifyOneShot(message, signature)
  }
}
object SHA3EdDSAKeyPair {
  import net.i2p.crypto.eddsa.EdDSAEngine
  import org.spongycastle.jcajce.provider.digest.SHA3
  import scala.util.Try

  private case class impl(publicKey: SHA3EdDSAPublicKey, privateKey: SHA3EdDSAPrivateKey) extends SHA3EdDSAKeyPair

  private val engine = new EdDSAEngine(new SHA3.Digest256)

  //FIXME: possibly deprecate this constructor
  @deprecated
  def apply(publicKey: SHA3EdDSAPublicKey, privateKey: SHA3EdDSAPrivateKey): Try[SHA3EdDSAKeyPair] = Try {
    new impl(publicKey, privateKey)
  }

  def apply(privateKey: SHA3EdDSAPrivateKey): Try[SHA3EdDSAKeyPair] =
    SHA3EdDSAPublicKey(privateKey.toPublicKeyBytes)
      .map(publicKey => new impl(publicKey, privateKey))
}
