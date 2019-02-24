package net.cimadai.crypto

/**
  * Copyright Richard Gomes -  All Rights Reserved.
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

import net.i2p.crypto.eddsa.math.GroupElement


trait SHA3EdDSAPublicKey {
  val A: GroupElement
  def toPublicKeyBytes: Array[Byte]
  def toPublicKeyHex: String
}
object SHA3EdDSAPublicKey {
  import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec
  import net.i2p.crypto.eddsa.{EdDSAPublicKey, Utils}
  import scala.util.Try

  private case class impl(self: EdDSAPublicKey) extends SHA3EdDSAPublicKey {
    val A: GroupElement = self.getA
    def toPublicKeyBytes: Array[Byte] = self.getAbyte
    def toPublicKeyHex: String = Utils.bytesToHex(this.toPublicKeyBytes)
  }

  private lazy val spec = SHA3EdDSAParameter.spec

  def apply(seed: Array[Byte]): Try[SHA3EdDSAPublicKey] = Try {
    new impl(
      new EdDSAPublicKey(
        new EdDSAPublicKeySpec(seed, spec)))
  }
}
