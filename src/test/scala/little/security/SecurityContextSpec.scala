/*
 * Copyright 2020 Carlos Conyers
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package little.security

class SecurityContextSpec extends org.scalatest.flatspec.AnyFlatSpec {
  val create = Permission("create")
  val select = Permission("select")
  val insert = Permission("insert")
  val update = Permission("update")
  val delete = Permission("delete")
  val guest1 = UserPermission("guest", "staff")
  val guest2 = UserPermission("guest", "admin")
  val root   = UserPermission("root", "wheel")
  val staff  = GroupPermission("staff")
  val wheel  = GroupPermission("wheel")

  val security = UserSecurity("guest", "staff", select, update)
  val empty = Set.empty[Permission]

  it should "grant permissions" in {
    val s1 = UserSecurity("guest", "staff", select, update)
    assert(s1.test(select))
    assert(s1.test(update))

    val s2 = s1.grant(insert)
    assert(s2.test(select))
    assert(s2.test(update))
    assert(s2.test(insert))

    val s3 = s1.grant(insert, delete)
    assert(s3.test(select))
    assert(s3.test(update))
    assert(s3.test(insert))
    assert(s3.test(delete))
  }

  it should "revoke permissions" in {
    val s1 = UserSecurity("guest", "staff", select, update)
    assert(s1.test(select))
    assert(s1.test(update))

    val s2 = s1.revoke(update)
    assert(s2.test(select))
    assert(!s2.test(update))

    val s3 = s1.revoke(select, update)
    assert(!s3.test(select))
    assert(!s3.test(update))
  }

  it should "authorize operation" in {
    assert { security(select)(() => 1) == 1 }
    assert { security(update)(() => 1) == 1 }

    assert { security(guest1)(() => 1) == 1 }
    assert { security(staff)(() => 1) == 1 }
  }

  it should "not authorize operation" in {
    assertThrows[SecurityViolation] { security(insert)(() => 1) }
    assertThrows[SecurityViolation] { security(delete)(() => 1) }

    assertThrows[SecurityViolation] { security(guest2)(() => 1) }
    assertThrows[SecurityViolation] { security(root)(() => 1) }
    assertThrows[SecurityViolation] { security(wheel)(() => 1) }
  }

  it should "authorize operation for any permission" in {
    assert { security.forAny(select, create, insert)(() => 1) == 1 }
    assert { security.forAny(insert, select, create)(() => 1) == 1 }
    assert { security.forAny(create, insert, select)(() => 1) == 1 }

    assert { security.forAny(select, create, update)(() => 1) == 1 }
    assert { security.forAny(update, select, create)(() => 1) == 1 }
    assert { security.forAny(create, update, select)(() => 1) == 1 }

    assert { security.forAny(select, update)(() => 1) == 1 }
    assert { security.forAny(update, select)(() => 1) == 1 }

    assert { security.forAny(select)(() => 1) == 1 }
    assert { security.forAny(update)(() => 1) == 1 }

    assert { security.forAny(empty)(() => 1) == 1 }
  }

  it should "not authorize operation for any permission" in {
    assertThrows[SecurityViolation] { security.forAny(insert, create, delete)(() => 1) }
    assertThrows[SecurityViolation] { security.forAny(insert, create)(() => 1) }
    assertThrows[SecurityViolation] { security.forAny(insert)(() => 1) }
    assertThrows[SecurityViolation] { security.forAny(guest2, root, wheel)(() => 1) }
  }

  it should "authorize operation for all permission" in {
    assert { security.forAll(select, update)(() => 1) == 1 }
    assert { security.forAll(update, select)(() => 1) == 1 }

    assert { security.forAll(update, select, update)(() => 1) == 1 }

    assert { security.forAll(select)(() => 1) == 1 }
    assert { security.forAll(update)(() => 1) == 1 }

    assert { security.forAll(empty)(() => 1) == 1 }
  }

  it should "not authorize operation for all permission" in {
    assertThrows[SecurityViolation] { security.forAll(select, create, insert)(() => 1) }
    assertThrows[SecurityViolation] { security.forAll(insert, select, create)(() => 1) }
    assertThrows[SecurityViolation] { security.forAll(create, insert, select)(() => 1) }

    assertThrows[SecurityViolation] { security.forAll(select, create, update)(() => 1) }
    assertThrows[SecurityViolation] { security.forAll(update, select, create)(() => 1) }
    assertThrows[SecurityViolation] { security.forAll(create, update, select)(() => 1) }

    assertThrows[SecurityViolation] { security.forAll(insert, update)(() => 1) }
    assertThrows[SecurityViolation] { security.forAll(update, insert)(() => 1) }
    assertThrows[SecurityViolation] { security.forAll(insert, select)(() => 1) }
    assertThrows[SecurityViolation] { security.forAll(select, insert)(() => 1) }

    assertThrows[SecurityViolation] { security.forAll(create)(() => 1) }
    assertThrows[SecurityViolation] { security.forAll(insert)(() => 1) }
  }
}
