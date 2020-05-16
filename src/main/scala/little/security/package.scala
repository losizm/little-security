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
package little

/**
 * Defines security model based on permissions granted to effective context.
 *
 * == How It Works ==
 *
 *  '''little-security''' is powered by a pair of traits: [[Permission]] and
 * [[SecurityContext]].
 * 
 * A `Permission` is defined by a given name, and one or more permissions can
 * be applied to a restricted operation.
 * 
 * A `SecurityContext` establishes a pattern in which a restricted operation is
 * performed only if its required permissions are granted. Otherwise, a
 * [[SecurityViolation]] is raised.
 *
 * == Security in Action ==
 *
 * The following script provides an example of how read/write access to an
 * in-memory cache can be regulated.
 *
 * {{{
 * import scala.collection.concurrent.TrieMap
 *
 * object SecureCache {
 *   // Define permissions for reading and writing cache entries
 *   private val getPermission = Permission("cache:get")
 *   private val setPermission = Permission("cache:set")
 *
 *   private val cache = TrieMap[String, Array[Byte]](
 *     "gang starr"      -> "step in the arena".getBytes("utf-8"),
 *     "digable planets" -> "blowout comb".getBytes("utf-8")
 *   )
 *
 *   def get(key: String)(implicit security: SecurityContext): Array[Byte] =
 *     // Tests for read permission before getting cache entry
 *     security(getPermission) { () =>
 *       copy(cache(key))
 *     }
 *
 *   def set(key: String, data: Array[Byte])(implicit security: SecurityContext): Unit =
 *     // Tests for write permission before setting cache entry
 *     security(setPermission) { () =>
 *       cache += key -> copy(data)
 *     }
 *
 *   private def copy(data: Array[Byte]): Array[Byte] =
 *     Array.copyOf(data, data.size)
 * }
 *
 * // Create security context for user with read permission to cache
 * implicit val user = UserSecurity("guest", "staff", Permission("cache:get"))
 *
 * // Get cache entry
 * val data = SecureCache.get("gang starr")
 *
 * // Throw SecurityViolation because user lacks write permission
 * SecureCache.set("sucker mc", data)
 *
 * }}}
 */
package object security
