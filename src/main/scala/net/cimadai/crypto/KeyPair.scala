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

sealed trait KeyPair {
  val inner: java.security.KeyPair
  val publicKey : PublicKey
  val privateKey: PrivateKey
}
object  KeyPair {
  import Implicits._
  import jp.co.soramitsu.crypto.ed25519.{EdDSAPrivateKey, EdDSAPublicKey}
  import scala.util.Try

  private case class impl(inner: java.security.KeyPair, publicKey: PublicKey, privateKey: PrivateKey) extends KeyPair

  /** Create a [SHA3EdDSAKeyPair] from [SHA3EdDSAPublicKey] and [SHA3EdDSAPrivateKey]. */
  def apply(publicKey: PublicKey, privateKey: PrivateKey): KeyPair =
    new impl(new java.security.KeyPair(publicKey.inner, privateKey.inner), publicKey, privateKey)

  /**
    * Create a [SHA3EdDSAKeyPair] from a [String].
    * @param seed is the private key
    */
  def apply(seed: String): Try[KeyPair] =
    seed.bytes
      .flatMap(bytes => apply(bytes))

  /**
    * Create a [SHA3EdDSAKeyPair] from a byte array.
    * @param seed the private key
    */
  def apply(seed: Array[Byte]): Try[KeyPair] = {
    assume(seed.length == 32)
    assume(seed.hexa.forall(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
    for {
      privateKey <- PrivateKey(seed)
      publicKey  <- PublicKey(privateKey.publicKeyBytes)
    } yield {
      apply(publicKey, privateKey)
    }
  }

  /**
    * Create a random [SHA3EdDSAKeyPair].
    */
  def random: Try[KeyPair] =
    randomKeyPair
      .map { kp =>
        apply(
          PublicKey(kp.getPublic.asInstanceOf[EdDSAPublicKey]),
          PrivateKey(kp.getPrivate.asInstanceOf[EdDSAPrivateKey])) }

  private def randomKeyPair: Try[java.security.KeyPair] =
    Try { Crypto.crypto.generateKeypair }

}
