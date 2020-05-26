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

/** Defines permission by name. */
sealed trait Permission {
  /** Gets name. */
  def name: String
}

/**
 * Provides `Permission` factory.
 *
 * @see [[UserPermission]], [[GroupPermission]]
 */
object Permission {
  /**
   * Creates permission with supplied name.
   *
   * @param name permission name
   *
   * @throws IllegalArgumentException if name is blank
   */
  def apply(name: String): Permission =
    name.trim() match {
      case ""    => throw new IllegalArgumentException()
      case value => PermissionImpl(name.trim())
    }

  /**
   * Creates set of permissions with supplied names.
   *
   * @param names permission names
   */
  def toSet(names: Iterable[String]): Set[Permission] =
    names.toSet.map(apply)

  /**
   * Creates set of permissions with supplied names.
   *
   * @param one permission name
   * @param more additional permission names
   */
  def toSet(one: String, more: String*): Set[Permission] =
    toSet(one +: more)

  /**
   * Destructures permission to its name
   *
   * @param perm permission
   */
  def unapply(perm: Permission): Option[String] =
    perm match {
      case null => None
      case _    => Some(perm.name)
    }
}

/**
 * Provides factory for creating user permissions.
 *
 * A user permission should be applied to operations that must be restricted to
 * a specific user. For example, if a user owns a resource, then write access to
 * the resource can be restricted to the user.
 *
 * @see [[GroupPermission]]
 */
object UserPermission {
  private val nameRegex = """<\[\[user=\((.*)\)\]\]>""".r

  /**
   * Creates user permission with supplied user identifier.
   *
   * @param userId user identifier
   */
  def apply(userId: String): Permission =
    PermissionImpl(s"<[[user=(${userId.trim()})]]>")

  /**
   * Creates set of user permissions with supplied identifiers.
   *
   * @param ids user identifiers
   */
  def toSet(ids: Iterable[String]): Set[Permission] =
    ids.toSet.map(apply)

  /**
   * Creates set of user permissions with supplied identifiers.
   *
   * @param one user identifier
   * @param more additional user identifiers
   */
  def toSet(one: String, more: String*): Set[Permission] =
    toSet(one +: more)

  /**
   * Destructures user permission to its user identifier.
   *
   * @param perm permission
   */
  def unapply(perm: Permission): Option[String] =
    perm match {
      case Permission(nameRegex(userId)) => Some(userId)
      case _                             => None
    }
}

/**
 * Provides factory for creating group permissions.
 *
 * A group permission should be applied to operations that must be restricted to
 * a specific group of users. For example, if a user owns a resource, then read
 * access to the resource can be restricted to the user's group.
 *
 * @see [[UserPermission]]
 */
object GroupPermission {
  private val nameRegex = """<\[\[group=\((.*)\)\]\]>""".r

  /**
   * Creates group permission with supplied group identifier.
   *
   * @param groupId group identifier
   */
  def apply(groupId: String): Permission =
    PermissionImpl(s"<[[group=(${groupId.trim()})]]>")

  /**
   * Creates set of group permissions with supplied identifiers.
   *
   * @param ids group identifiers
   */
  def toSet(ids: Iterable[String]): Set[Permission] =
    ids.toSet.map(apply)

  /**
   * Creates set of group permissions with supplied identifiers.
   *
   * @param one group identifier
   * @param more additional group identifiers
   */
  def toSet(one: String, more: String*): Set[Permission] =
    toSet(one +: more)

  /**
   * Destructures group permission to its group identifier.
   *
   * @param perm permission
   */
  def unapply(perm: Permission): Option[String] =
    perm match {
      case Permission(nameRegex(groupId)) => Some(groupId)
      case _                              => None
    }
}

private case class PermissionImpl(name: String) extends Permission {
  override lazy val toString = s"Permission($name)"
}
