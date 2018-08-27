package net.cimadai.iroha

import org.scalatest.WordSpec

class IrohaValidatorSpec extends WordSpec {
  "IrohaValidator.DomainParser" can {
    "parse abc" in assert(IrohaValidator.DomainParser("abc").isRight, true)
    "parse abc.xx" in assert(IrohaValidator.DomainParser("abc.xx").isRight, true)
    "parse abc.xx.yy" in assert(IrohaValidator.DomainParser("abc.xx.yy").isRight, true)
    "parse abc.xx.yy.zz" in assert(IrohaValidator.DomainParser("abc.xx.yy.zz").isRight, true)
  }
}
