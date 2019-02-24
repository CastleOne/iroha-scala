package net.cimadai.iroha

import utest._

object IrohaValidatorSpec extends TestSuite {
  class dummy extends Iroha.Validation
  val tests = this {
    "parse domains names"-{
      val o = new dummy
      "parse abc"          - { assert(o.parseDomainName("abc").isSuccess) }
      "parse abc.xx"       - { assert(o.parseDomainName("abc.xx").isSuccess) }
      "parse abc.xx.yy"    - { assert(o.parseDomainName("abc.xx.yy").isSuccess) }
      "parse abc.xx.yy.zz" - { assert(o.parseDomainName("abc.xx.yy.zz").isSuccess) }
    }
  }
}
