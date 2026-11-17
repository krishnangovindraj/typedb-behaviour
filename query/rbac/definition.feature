# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

#noinspection CucumberUndefinedStep
Feature: Defining RBAC roles

  Background:
    Given typedb starts
    Given connection opens with default authentication
    Given connection is open: true
    Given connection has 0 databases
    Given connection create database: typedb

  Scenario: RBAC roles can be defined & read back
    Given connection open schema transaction for database: typedb

    Given typeql schema query
    """
    define
      attribute email, value string;
      attribute text, value string;
      attribute views, value integer;

      relation authorship,
        relates content @card(1),
        relates author;


      entity post,
        owns text, owns views,
        plays authorship:content;
      entity comment,
        owns text, owns views,
        plays authorship:content;
      entity user,
        owns email,
        plays authorship:author;

      rbac post-readers,
        reads { post, comment, user },
        writes { views };
    """
    Given transaction commits

    Given connection open read transaction for database: typedb
    Then list rbac declared access for role: post-readers
      | type    | access |
      | post    | read   |
      | comment | read   |
      | user    | read   |
      | views   | write  |

    Then rbac role 'post-readers' has read access on type 'post': true
    Then rbac role 'post-readers' has read access on type 'comment': true
    Then rbac role 'post-readers' has read access on type 'user': true
    # Write access implies read access?
    # Then rbac role 'post-readers' has read access on type 'views': true

    Then rbac role 'post-readers' has write access on type 'post': false
    Then rbac role 'post-readers' has write access on type 'comment': false
    Then rbac role 'post-readers' has write access on type 'user': false
    Then rbac role 'post-readers' has write access on type 'views': true
