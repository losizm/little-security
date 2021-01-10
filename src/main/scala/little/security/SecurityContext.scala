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

/** Defines context in which permissions are granted. */
sealed trait SecurityContext {
  /**
   * Tests whether given permission is granted.
   *
   * @param perm permission
   *
   * @return `true` if permission is granted; otherwise, `false`
   */
  def test(perm: Permission): Boolean

  /**
   * Tests permission before applying operation.
   *
   * If supplied permission is granted, the operation is applied; otherwise,
   * [[SecurityViolation]] is thrown.
   *
   * @param perm permission
   * @param op operation
   *
   * @return value of operation
   *
   * @throws SecurityViolation if permission is not granted
   */
  def apply[T](perm: Permission)(op: => T): T =
    test(perm) match {
      case true  => op
      case false => throw SecurityViolation(s"Permission not granted: $perm")
    }

  /**
   * Tests permissions before applying operation.
   *
   * If any of supplied permissions is granted, the operation is applied;
   * otherwise, [[SecurityViolation]] is thrown.
   *
   * @param perms permissions
   * @param op operation
   *
   * @return value of operation
   *
   * @throws SecurityViolation if no permission is granted
   *
   * @note The operation is authorized if `perms` is empty.
   */
  def any[T](perms: Set[Permission])(op: => T): T =
    (perms.isEmpty || perms.exists(test)) match {
      case true  => op
      case false => throw SecurityViolation(s"No permission granted: ${perms.mkString(", ")}"
      )
    }

  /**
   * Tests permissions before applying operation.
   *
   * If any of supplied permissions is granted, the operation is applied;
   * otherwise, [[SecurityViolation]] is thrown.
   *
   * @param one permission
   * @param more additional permissions
   * @param op operation
   *
   * @return value of operation
   *
   * @throws SecurityViolation if no permission is granted
   */
  def any[T](one: Permission, more: Permission*)(op: => T): T =
    any((one +: more).toSet)(op)

  /**
   * Tests permissions before applying operation.
   *
   * If all supplied permissions are granted, the operation is applied;
   * otherwise, [[SecurityViolation]] is thrown.
   *
   * @param perms permissions
   * @param op operation
   *
   * @return value of operation
   *
   * @throws SecurityViolation if all permissions are not granted
   *
   * @note The operation is authorized if `perms` is empty.
   */
  def all[T](perms: Set[Permission])(op: => T): T =
    perms.find(!test(_)) match {
      case Some(perm) => throw SecurityViolation(s"Permission not granted: $perm")
      case None       => op
    }

  /**
   * Tests permissions before applying operation.
   *
   * If all supplied permissions are granted, the operation is applied;
   * otherwise, [[SecurityViolation]] is thrown.
   *
   * @param one permission
   * @param more additional permissions
   * @param op operation
   *
   * @return value of operation
   *
   * @throws SecurityViolation if all permissions are not granted
   */
  def all[T](one: Permission, more: Permission*)(op: => T): T =
    all((one +: more).toSet)(op)
}

/**
 * Defines root context in which all permissions are granted.
 *
 * @see [[UserContext]]
 */
object RootContext extends SecurityContext {
  /**
   * @inheritdoc
   *
   * @return `true`
   */
  def test(perm: Permission): Boolean = true

  /** Gets string representation. */
  override val toString = "RootContext"
}

/**
 * Defines user context in which a set of permissions is granted.
 *
 * @see [[RootContext]]
 */
sealed trait UserContext extends SecurityContext {
  /** Gets user identifier. */
  def userId: String

  /** Gets group identifier. */
  def groupId: String

  /** Gets permissions. */
  def permissions: Set[Permission]

  /**
   * Creates new security context by replacing existing permissions with
   * supplied permissions.
   *
   * @param perms permissions
   *
   * @return new security context
   */
  def withPermissions(perms: Set[Permission]): UserContext

  /**
   * Creates new security context by replacing existing permissions with
   * supplied permissions.
   *
   * @param one permission
   * @param more additional permissions
   *
   * @return new security context
   */
  def withPermissions(one: Permission, more: Permission*): UserContext =
    withPermissions((one +: more).toSet)

  /**
   * Creates new security context by adding supplied permissions to existing set
   * of permissions.
   *
   * @param perms permissions
   *
   * @return new security context
   */
  def grant(perms: Set[Permission]): UserContext =
    withPermissions(permissions ++ perms)

  /**
   * Creates new security context by adding supplied permissions to existing set
   * of permissions.
   *
   * @param one permission
   * @param more additional permissions
   *
   * @return new security context
   */
  def grant(one: Permission, more: Permission*): UserContext =
    grant((one +: more).toSet)

  /**
   * Creates new security context by removing supplied permissions from existing
   * set of permissions.
   *
   * @param perms permissions
   *
   * @return new security context
   */
  def revoke(perms: Set[Permission]): UserContext =
    withPermissions(permissions.diff(perms))

  /**
   * Creates new security context by removing supplied permissions from existing
   * set of permissions.
   *
   * @param one permission
   * @param more additional permissions
   *
   * @return new security context
   */
  def revoke(one: Permission, more: Permission*): UserContext =
    revoke((one +: more).toSet)
}

/** Provides `UserContext` factory. */
object UserContext {
  /**
   * Creates `UserContext` with supplied identity.
   *
   * @param userId user identifier
   * @param groupId group identifier
   *
   * @note User and group permissions added to security context.
   */
  def apply(userId: String, groupId: String): UserContext =
    apply(userId, groupId, Set.empty[Permission])

  /**
   * Creates `UserContext` with supplied identity and permissions.
   *
   * @param userId user identifier
   * @param groupId group identifier
   * @param permissions permissions
   *
   * @note User and group permissions are added to set of supplied permissions.
   */
  def apply(userId: String, groupId: String, permissions: Set[Permission]): UserContext = {
    val uid = userId.trim()
    val gid = groupId.trim()

    UserContextImpl(uid, gid, permissions + UserPermission(uid) + GroupPermission(gid))
  }

  /**
   * Creates `UserContext` with supplied identity and permissions.
   *
   * @param userId user identifier
   * @param groupId group identifier
   * @param one permission
   * @param more additional permissions
   *
   * @note User and group permissions are added to set of supplied permissions.
   */
  def apply(userId: String, groupId: String, one: Permission, more: Permission*): UserContext =
    apply(userId, groupId, (one +: more).toSet)

  /**
   * Destructures user context to its `userId`, `groupId`, and `permissions`.
   *
   * @param security user context
   */
  def unapply(security: UserContext): Option[(String, String, Set[Permission])] =
    security match {
      case null => None
      case _    => Some((security.userId, security.groupId, security.permissions))
    }
}

private case class UserContextImpl(userId: String, groupId: String, permissions: Set[Permission]) extends UserContext {
  def test(perm: Permission): Boolean =
    permissions.contains(perm)

  def withPermissions(perms: Set[Permission]): UserContext =
    copy(permissions = perms)

  override lazy val toString = s"UserContext($userId,$groupId,$permissions)"
}
