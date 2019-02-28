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



sealed trait SHA3EdDSAPrivateKey {
  import jp.co.soramitsu.crypto.ed25519.EdDSAPrivateKey
  import scala.util.Try
  import java.nio.charset.Charset
  val ctx: SHA3EdDSAContext
  val inner: EdDSAPrivateKey
  /** Returns the public key as a byte array. */
  def publicKeyBytes: Array[Byte]
  /** Returns the public key as an hexadecimal [String]. */
  def publicKeyHexa: String
  /** Returns the private key as a byte array. */
  def bytes: Array[Byte]
  /** Returns the private key as an hexadecimal [String]. */
  def hexa: String
  /** Signs a message [String] under a certain [Charset]. */
  def sign(message: String, charset: Charset): Try[Array[Byte]]
  /** Signs a message [String]. */
  def sign(message: String): Try[Array[Byte]]
  /** Signs a byte array. */
  def sign(message: Array[Byte]): Try[Array[Byte]]
}
object SHA3EdDSAPrivateKey {
  import Implicits._
  import jp.co.soramitsu.crypto.ed25519.EdDSAPrivateKey
  import scala.util.Try

  private case class impl(ctx: SHA3EdDSAContext, inner: EdDSAPrivateKey) extends SHA3EdDSAPrivateKey {
    import scala.util.Try
    import java.nio.charset.Charset

    def publicKeyBytes: Array[Byte] = inner.getAbyte
    def publicKeyHexa: String = publicKeyBytes.hexa
    def bytes: Array[Byte] = inner.geta
    def hexa: String = bytes.hexa
    def sign(message: String, charset: Charset): Try[Array[Byte]] = sign(message.getBytes(charset))
    def sign(message: String): Try[Array[Byte]] = sign(message.getBytes)
    def sign(message: Array[Byte]): Try[Array[Byte]] = Try {
      ctx.engine.initSign(inner)
      ctx.engine.signOneShot(message)
    }
  }

  /**
    * Create a [SHA3EdDSAPrivateKey] from a [EdDSAPrivateKey].
    * @param seed is the private key
    */
  def apply(privateKey: EdDSAPrivateKey)(implicit ctx: SHA3EdDSAContext): Try[SHA3EdDSAPrivateKey] = Try {
    impl(ctx, privateKey)
  }

  /**
    * Create a [SHA3EdDSAPrivateKey] from a [String].
    * @param seed is the private key
    */
  def apply(seed: String)(implicit ctx: SHA3EdDSAContext): Try[SHA3EdDSAPrivateKey] =
    apply(seed.bytes)

  /**
    * Create a [SHA3EdDSAPrivateKey] from a byte array.
    * @param seed the private key
    */
  def apply(seed: Array[Byte])(implicit ctx: SHA3EdDSAContext): Try[SHA3EdDSAPrivateKey] = Try {
    import jp.co.soramitsu.crypto.ed25519.spec.EdDSAPrivateKeySpec
    assume(seed.length == 32)
    assume(seed.hexa.forall(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
    new impl(
      ctx,
      new EdDSAPrivateKey(
        new EdDSAPrivateKeySpec(seed, ctx.spec)))
  }
}
