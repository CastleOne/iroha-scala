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

import net.i2p.crypto.eddsa.math.{Curve, GroupElement, ScalarOps}
import net.i2p.crypto.eddsa.spec.{EdDSANamedCurveTable, EdDSAParameterSpec}


trait SHA3EdDSAParameter {
  /** Returns a twisted Edwards elliptic curve. */
  val curve: Curve
  /** Return the hashing algorithm. */
  val hashAlgo: String
  /** Return scalar operations. */
  val sc: ScalarOps
  /** Return the base generator. */
  val B: GroupElement
}
object SHA3EdDSAParameter {
  import scala.util.Try

  private case class impl(self: EdDSAParameterSpec) extends SHA3EdDSAParameter {
    val curve: Curve = self.getCurve
    val hashAlgo: String = self.getHashAlgorithm
    val sc: ScalarOps = self.getScalarOps
    val B: GroupElement = self.getB
  }

  private[crypto] lazy val spec = EdDSANamedCurveTable.getByName("Ed25519")
  private lazy val instance =
    new impl(
      new EdDSAParameterSpec(
        spec.getCurve, spec.getHashAlgorithm, spec.getScalarOps, spec.getB))

  def apply: Try[SHA3EdDSAParameter] = Try { instance }
}
