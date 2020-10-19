#
# Copyright (C) 2020 Grakn Labs
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

#noinspection CucumberUndefinedStep
Feature: Graql Insert Query

  Background: Open connection and create a simple extensible schema
    Given connection has been opened
    Given connection delete all databases
    Given connection does not have any database
    Given connection create database: grakn
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given the integrity is validated
    Given graql define
      """
      define

      person sub entity,
        plays employment:employee,
        owns name,
        owns age,
        owns ref @key;

      company sub entity,
        plays employment:employer,
        owns name,
        owns ref @key;

      employment sub relation,
        relates employee,
        relates employer,
        owns ref @key;

      name sub attribute,
        value string;

      age sub attribute,
        value long;

      ref sub attribute,
        value long;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write


  ####################
  # INSERTING THINGS #
  ####################

  Scenario: new entities can be inserted
    When graql insert
      """
      insert $x isa person, has ref 0;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $x isa person;
      """
    When concept identifiers are
      |     | check | value |
      | PER | key   | ref:0 |
    Then uniquely identify answer concepts
      | x   |
      | PER |


  Scenario: one query can insert multiple things
    When graql insert
      """
      insert
      $x isa person, has ref 0;
      $y isa person, has ref 1;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $x isa person;
      """
    When concept identifiers are
      |      | check | value |
      | REF0 | key   | ref:0 |
      | REF1 | key   | ref:1 |
    Then uniquely identify answer concepts
      | x    |
      | REF0 |
      | REF1 |


  Scenario: when an insert has multiple statements with the same variable name, they refer to the same thing
    When graql insert
      """
      insert
      $x has name "Bond";
      $x has name "James Bond";
      $x isa person, has ref 0;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $x has name "Bond";
      """
    When concept identifiers are
      |      | check | value |
      | BOND | key   | ref:0 |
    Then uniquely identify answer concepts
      | x    |
      | BOND |
    When get answers of graql query
      """
      match $x has name "James Bond";
      """
    Then uniquely identify answer concepts
      | x    |
      | BOND |
    When get answers of graql query
      """
      match $x has name "Bond", has name "James Bond";
      """
    Then uniquely identify answer concepts
      | x    |
      | BOND |


  Scenario: when running multiple identical insert queries in series, new things get created each time
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      breed sub attribute, value string;
      dog sub entity, owns breed;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    Given get answers of graql query
      """
      match $x isa dog;
      """
    Given answer size is: 0
    When graql insert
      """
      insert $x isa dog, has breed "Labrador";
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When get answers of graql query
      """
      match $x isa dog;
      """
    Then answer size is: 1
    Then graql insert
      """
      insert $x isa dog, has breed "Labrador";
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When get answers of graql query
      """
      match $x isa dog;
      """
    Then answer size is: 2
    Then graql insert
      """
      insert $x isa dog, has breed "Labrador";
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $x isa dog;
      """
    Then answer size is: 3


  Scenario: an insert can be performed using a direct type specifier, and it functions equivalently to 'isa'
    When get answers of graql insert
      """
      insert $x isa! person, has name "Harry", has ref 0;
      """
    Then the integrity is validated
    When concept identifiers are
      |     | check | value |
      | HAR | key   | ref:0 |
    Then uniquely identify answer concepts
      | x   |
      | HAR |


  Scenario: attempting to insert an instance of an abstract type throws an error
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      factory sub entity, abstract;
      electronics-factory sub factory;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    Then graql insert; throws exception
      """
      insert $x isa factory;
      """
    Then the integrity is validated


  Scenario: attempting to insert an instance of type 'thing' throws an error
    Then graql insert; throws exception
      """
      insert $x isa thing;
      """
    Then the integrity is validated


  #######################
  # ATTRIBUTE OWNERSHIP #
  #######################

  Scenario: when inserting a new thing that owns new attributes, both the thing and the attributes get created
    Given get answers of graql query
      """
      match $x isa thing;
      """
    Given answer size is: 0
    When graql insert
      """
      insert $x isa person, has name "Wilhelmina", has age 25, has ref 0;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $x isa thing;
      """
    When concept identifiers are
      |      | check | value           |
      | WIL  | key   | ref:0           |
      | nWIL | value | name:Wilhelmina |
      | a25  | value | age:25          |
      | REF0 | value | ref:0           |
    Then uniquely identify answer concepts
      | x    |
      | WIL  |
      | nWIL |
      | a25  |
      | REF0 |


  Scenario: a freshly inserted attribute has no owners
    Given graql insert
      """
      insert $name "John" isa name;
      """
    Given transaction commits
    Given the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $x has name "John";
      """
    Then answer size is: 0


  Scenario: given an attribute with no owners, inserting a thing that owns it results in it having an owner
    Given graql insert
      """
      insert $name "Kyle" isa name;
      """
    Given transaction commits
    Given the integrity is validated
    When session opens transaction of type: write
    Given graql insert
      """
      insert $x isa person, has name "Kyle", has ref 0;
      """
    Given transaction commits
    Given the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $x has name "Kyle";
      """
    When concept identifiers are
      |      | check | value |
      | KYLE | key   | ref:0 |
    Then uniquely identify answer concepts
      | x    |
      | KYLE |


  Scenario: after inserting two things that own the same attribute, the attribute has two owners
    When graql insert
      """
      insert
      $p1 isa person, has name "Jack", has age 10, has ref 0;
      $p2 isa person, has name "Jill", has age 10, has ref 1;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match
      $p1 isa person, has age $a;
      $p2 isa person, has age $a;
      $p1 != $p2;
      get $p1, $p2;
      """
    When concept identifiers are
      |      | check | value |
      | JACK | key   | ref:0 |
      | JILL | key   | ref:1 |
    Then uniquely identify answer concepts
      | p1   | p2   |
      | JACK | JILL |
      | JILL | JACK |


  Scenario: after inserting a new owner for every existing ownership of an attribute, its number of owners doubles
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      dog sub entity, owns name;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    Given graql insert
      """
      insert
      $p1 isa dog, has name "Frank";
      $p2 isa dog, has name "Geoff";
      $p3 isa dog, has name "Harriet";
      $p4 isa dog, has name "Ingrid";
      $p5 isa dog, has name "Jacob";
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    When get answers of graql query
      """
      match $p isa dog;
      """
    Then answer size is: 5
    When graql insert
      """
      match
        $p has name $name;
      insert
        $p2 isa dog, has name $name;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When get answers of graql query
      """
      match $p isa dog;
      """
    Then answer size is: 10


  Scenario Outline: an insert can attach multiple distinct values of the same <type> attribute to a single owner
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      <attr> sub attribute, value <type>, owns ref @key;
      person owns <attr>;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    When graql insert
      """
      insert
      $x <val1> isa <attr>, has ref 0;
      $y <val2> isa <attr>, has ref 1;
      $p isa person, has name "Imogen", has ref 2, has <attr> <val1>, has <attr> <val2>;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $p isa person, has <attr> $x; get $x;
      """
    When concept identifiers are
      |      | check | value |
      | VAL1 | key   | ref:0 |
      | VAL2 | key   | ref:1 |
    Then uniquely identify answer concepts
      | x    |
      | VAL1 |
      | VAL2 |

    Examples:
      | attr              | type     | val1       | val2       |
      | subject-taken     | string   | "Maths"    | "Physics"  |
      | lucky-number      | long     | 10         | 3          |
      | recite-pi-attempt | double   | 3.146      | 3.14158    |
      | is-alive          | boolean  | true       | false      |
      | work-start-date   | datetime | 2018-01-01 | 2020-01-01 |


  Scenario: inserting an attribute onto a thing that can't have that attribute throws an error
    Then graql insert; throws exception
      """
      insert
      $x isa company, has ref 0, has age 10;
      """
    Then the integrity is validated


  ########################################
  # ADDING ATTRIBUTES TO EXISTING THINGS #
  ########################################

  Scenario: when an entity owns an attribute, an additional value can be inserted on it
    Given graql insert
      """
      insert
      $p isa person, has name "Peter Parker", has ref 0;
      """
    Given transaction commits
    Given the integrity is validated
    Given session opens transaction of type: write
    Given get answers of graql query
      """
      match $p has name "Spiderman";
      """
    Given answer size is: 0
    When graql insert
      """
      match
        $p isa person, has name "Peter Parker";
      insert
        $p has name "Spiderman";
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $p has name "Spiderman";
      """
    When concept identifiers are
      |     | check | value |
      | PET | key   | ref:0 |
    Then uniquely identify answer concepts
      | p   |
      | PET |


  Scenario: when inserting an additional attribute ownership on an entity, the entity type can be optionally specified
    Given graql insert
      """
      insert
      $p isa person, has name "Peter Parker", has ref 0;
      """
    Given transaction commits
    Given the integrity is validated
    Given session opens transaction of type: write
    Given get answers of graql query
      """
      match $p has name "Spiderman";
      """
    Given answer size is: 0
    When graql insert
      """
      match
        $p isa person, has name "Peter Parker";
      insert
        $p isa person, has name "Spiderman";
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $p has name "Spiderman";
      """
    When concept identifiers are
      |     | check | value |
      | PET | key   | ref:0 |
    Then uniquely identify answer concepts
      | p   |
      | PET |


  Scenario: when an attribute owns an attribute, an instance of that attribute can be inserted onto it
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      colour sub attribute, value string, owns hex-value;
      hex-value sub attribute, value string;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    Given graql insert
      """
      insert
      $c "red" isa colour;
      """
    Given transaction commits
    Given the integrity is validated
    Given session opens transaction of type: write
    Given get answers of graql query
      """
      match $c has hex-value "#FF0000";
      """
    Given answer size is: 0
    When graql insert
      """
      match
        $c "red" isa colour;
      insert
        $c has hex-value "#FF0000";
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $c has hex-value "#FF0000";
      """
    When concept identifiers are
      |     | check | value      |
      | COL | value | colour:red |
    Then uniquely identify answer concepts
      | c   |
      | COL |


  Scenario: when inserting an additional attribute ownership on an attribute, the owner type can be optionally specified
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      colour sub attribute, value string, owns hex-value;
      hex-value sub attribute, value string;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    Given graql insert
      """
      insert
      $c "red" isa colour;
      """
    Given transaction commits
    Given the integrity is validated
    Given session opens transaction of type: write
    Given get answers of graql query
      """
      match $c has hex-value "#FF0000";
      """
    Given answer size is: 0
    When graql insert
      """
      match
        $c "red" isa colour;
      insert
        $c isa colour, has hex-value "#FF0000";
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $c has hex-value "#FF0000";
      """
    When concept identifiers are
      |     | check | value      |
      | COL | value | colour:red |
    Then uniquely identify answer concepts
      | c   |
      | COL |


  Scenario: when linking an attribute that doesn't exist yet to a relation, the attribute gets created
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      residence sub relation,
        relates resident,
        relates place,
        owns tenure-days,
        owns ref @key;
      person plays residence:resident;
      address sub attribute, value string, plays residence:place;
      tenure-days sub attribute, value long;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    When graql insert
      """
      insert
      $p isa person, has name "Homer", has ref 0;
      $addr "742 Evergreen Terrace" isa address;
      $r (resident: $p, place: $addr) isa residence, has ref 0;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When get answers of graql query
      """
      match $td isa tenure-days;
      """
    Then answer size is: 0
    When graql insert
      """
      match
        $r isa residence;
      insert
        $r has tenure-days 365;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $r isa residence, has tenure-days $a; get $a;
      """
    When concept identifiers are
      |     | check | value           |
      | RES | key   | ref:0           |
      | TEN | value | tenure-days:365 |
    Then uniquely identify answer concepts
      | a   |
      | TEN |


  Scenario: an attribute ownership currently inferred by a rule can be explicitly inserted
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      rule lucy-is-aged-32:
      when {
        $p isa person, has name "Lucy";
      } then {
        $p has age 32;
      };
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    Given graql insert
      """
      insert $p isa person, has name "Lucy", has ref 0;
      """
    Given transaction commits
    Given the integrity is validated
    Given session opens transaction of type: write
    Given get answers of graql query
      """
      match $p has age 32;
      """
    Given concept identifiers are
      |      | check | value |
      | LUCY | key   | ref:0 |
    Given uniquely identify answer concepts
      | p    |
      | LUCY |
    Given graql insert
      """
      match
        $p has name "Lucy";
      insert
        $p has age 32;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $p has age 32;
      """
    Then uniquely identify answer concepts
      | p    |
      | LUCY |


  #############
  # RELATIONS #
  #############

  Scenario: new relations can be inserted
    When graql insert
      """
      insert
      $p isa person, has ref 0;
      $r (employee: $p) isa employment, has ref 1;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $r (employee: $p) isa employment;
      """
    When concept identifiers are
      |     | check | value |
      | PER | key   | ref:0 |
      | EMP | key   | ref:1 |
    Then uniquely identify answer concepts
      | p   | r   |
      | PER | EMP |


  Scenario: when inserting a relation that owns an attribute and has an attribute roleplayer, both attributes are created
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      residence sub relation,
        relates resident,
        relates place,
        owns is-permanent,
        owns ref @key;
      person plays residence:resident;
      address sub attribute, value string, plays residence:place;
      is-permanent sub attribute, value boolean;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    When graql insert
      """
      insert
      $p isa person, has name "Homer", has ref 0;
      $perm true isa is-permanent;
      $r (resident: $p, place: $addr) isa residence, has is-permanent $perm, has ref 0;
      $addr "742 Evergreen Terrace" isa address;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $r (place-of-residence: $addr) isa residence, has is-permanent $perm;
      """
    When concept identifiers are
      |     | check | value                         |
      | RES | key   | ref:0                         |
      | ADD | value | address:742 Evergreen Terrace |
      | PER | value | is-permanent:true             |
    Then uniquely identify answer concepts
      | r   | addr | perm |
      | RES | ADD  | PER  |


  Scenario: relations can be inserted with multiple role players
    When graql insert
      """
      insert
      $p1 isa person, has name "Gordon", has ref 0;
      $p2 isa person, has name "Helen", has ref 1;
      $c isa company, has name "Morrisons", has ref 2;
      $r (employer: $c, employee: $p1, employee: $p2) isa employment, has ref 3;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match
        $r (employer: $c) isa employment;
        $c has name $cname;
      get $cname;
      """
    When concept identifiers are
      |     | check | value          |
      | MOR | value | name:Morrisons |
    Then uniquely identify answer concepts
      | cname |
      | MOR   |
    When get answers of graql query
      """
      match
        $r (employee: $p) isa employment;
        $p has name $pname;
      get $pname;
      """
    When concept identifiers are
      |     | check | value       |
      | GOR | value | name:Gordon |
      | HEL | value | name:Helen  |


  Scenario: an additional role player can be inserted onto an existing relation
    Given graql insert
      """
      insert $p isa person, has ref 0; $r (employee: $p) isa employment, has ref 1;
      """
    Given transaction commits
    Given the integrity is validated
    When session opens transaction of type: write
    When graql insert
      """
      match
        $r isa employment;
      insert
        $r (employer: $c) isa employment;
        $c isa company, has ref 2;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $r (employer: $c, employee: $p) isa employment;
      """
    When concept identifiers are
      |      | check | value |
      | REF0 | key   | ref:0 |
      | REF1 | key   | ref:1 |
      | REF2 | key   | ref:2 |
    Then uniquely identify answer concepts
      | p    | c    | r    |
      | REF0 | REF2 | REF1 |


  Scenario: an additional role player can be inserted into every relation matching a pattern
    Given graql insert
      """
      insert
      $p isa person, has name "Ruth", has ref 0;
      $r (employee: $p) isa employment, has ref 1;
      $s (employee: $p) isa employment, has ref 2;
      $c isa company, has name "The Boring Company", has ref 3;
      """
    Given transaction commits
    Given the integrity is validated
    When session opens transaction of type: write
    When graql insert
      """
      match
        $r isa employment, has ref $ref;
        $c isa company;
      insert
        $r (employer: $c) isa employment;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $r (employer: $c, employee: $p) isa employment;
      """
    When concept identifiers are
      |      | check | value |
      | RUTH | key   | ref:0 |
      | EMP1 | key   | ref:1 |
      | EMP2 | key   | ref:2 |
      | COMP | key   | ref:3 |
    Then uniquely identify answer concepts
      | p    | c    | r    |
      | RUTH | COMP | EMP1 |
      | RUTH | COMP | EMP2 |


  Scenario: an additional duplicate role player can be inserted into an existing relation
    Given graql insert
      """
      insert $p isa person, has ref 0; $r (employee: $p) isa employment, has ref 1;
      """
    Given transaction commits
    Given the integrity is validated
    When session opens transaction of type: write
    When graql insert
      """
      match
        $r isa employment;
        $p isa person;
      insert
        $r (employee: $p) isa employment;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $r (employee: $p, employee: $p) isa employment;
      """
    When concept identifiers are
      |      | check | value |
      | REF0 | key   | ref:0 |
      | REF1 | key   | ref:1 |
    Then uniquely identify answer concepts
      | p    | r    |
      | REF0 | REF1 |


  Scenario: when inserting a roleplayer that can't play the role, an error is thrown
    Then graql insert; throws exception
      """
      insert
      $r (employer: $p) isa employment, has ref 0;
      $p isa person, has ref 1;
      """
    Then the integrity is validated


  Scenario: parent types are not necessarily allowed to play the roles that their children play
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      animal sub entity;
      cat sub animal, plays sphinx-production:model;
      sphinx-production sub relation, relates model, relates builder;
      person plays sphinx-production:builder;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    Then graql insert; throws exception
      """
      insert
      $r (model: $x, builder: $y) isa sphinx-production;
      $x isa animal;
      $y isa person, has ref 0;
      """
    Then the integrity is validated


  Scenario: when inserting a relation with no role players, an error is thrown
    Then graql insert; throws exception
      """
      insert
      $x isa employment, has ref 0;
      """
    Then the integrity is validated


  Scenario: when inserting a relation with an unbound variable as a roleplayer, an error is thrown
    Then graql insert; throws exception
      """
      insert
      $r (employee: $x, employer: $y) isa employment, has ref 0;
      $y isa company, has name "Sports Direct", has ref 1;
      """
    Then the integrity is validated


  Scenario: a relation currently inferred by a rule can be explicitly inserted
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      gym-membership sub relation, relates member;
      person plays gym-membership:member;
      rule jennifer-has-a-gym-membership:
      when {
        $p isa person, has name "Jennifer";
      } then {
        (member: $p) isa gym-membership;
      };
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    When graql insert
      """
      insert $p isa person, has name "Jennifer", has ref 0;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When get answers of graql query
      """
      match (member: $p) isa gym-membership; get $p;
      """
    When concept identifiers are
      |     | check | value |
      | JEN | key   | ref:0 |
    Then graql insert
      """
      match
        $p has name "Jennifer";
      insert
        $r (member: $p) isa gym-membership;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match (member: $p) isa gym-membership; get $p;
      """
    Then uniquely identify answer concepts
      | p   |
      | JEN |
    When get answers of graql query
      """
      match $r isa gym-membership; get $r;
      """
    Then answer size is: 1


  #######################
  # ATTRIBUTE INSERTION #
  #######################

  Scenario Outline: inserting an attribute of type '<type>' creates an instance of it
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define <attr> sub attribute, value <type>, owns ref @key;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    Given get answers of graql query
      """
      match $x <value> isa <attr>;
      """
    Given answer size is: 0
    When graql insert
      """
      insert $x <value> isa <attr>, has ref 0;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $x <value> isa <attr>;
      """
    When concept identifiers are
      |     | check | value |
      | ATT | key   | ref:0 |
    Then uniquely identify answer concepts
      | x   |
      | ATT |

    Examples:
      | attr           | type     | value      |
      | title          | string   | "Prologue" |
      | page-number    | long     | 233        |
      | price          | double   | 15.99      |
      | purchased      | boolean  | true       |
      | published-date | datetime | 2020-01-01 |


  Scenario: insert a regex attribute throws error if not conforming to regex
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      person sub entity,
        owns value;
      value sub attribute,
        value string,
        regex "\d{2}\.[true][false]";
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    Then graql insert; throws exception
      """
      insert
        $x isa person, has value $a, has ref 0;
        $a "10.maybe";
      """
    Then the integrity is validated


  Scenario: inserting two attributes with the same type and value creates only one concept
    When graql insert
      """
      insert
      $x 2 isa age;
      $y 2 isa age;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When concept identifiers are
      |      | check | value |
      | AGE2 | value | age:2 |
    When get answers of graql query
      """
      match $x isa age;
      """
    Then uniquely identify answer concepts
      | x    |
      | AGE2 |


  Scenario: inserting two 'double' attribute values with the same integer value creates a single concept
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      length sub attribute, value double;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    When graql insert
      """
      insert
      $x 2 isa length;
      $y 2 isa length;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When concept identifiers are
      |    | check | value      |
      | L2 | value | length:2.0 |
    When get answers of graql query
      """
      match $x isa length;
      """
    Then answer size is: 1
    Then uniquely identify answer concepts
      | x  |
      | L2 |


  Scenario: inserting the same integer twice as a 'double' in separate transactions creates a single concept
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      length sub attribute, value double;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    When graql insert
      """
      insert
      $x 2 isa length;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When graql insert
      """
      insert
      $y 2 isa length;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When concept identifiers are
      |    | check | value      |
      | L2 | value | length:2.0 |
    When get answers of graql query
      """
      match $x isa length;
      """
    Then answer size is: 1
    Then uniquely identify answer concepts
      | x  |
      | L2 |


  Scenario: inserting attribute values [2] and [2.0] with the same attribute type creates a single concept
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      length sub attribute, value double;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    When graql insert
      """
      insert
      $x 2 isa length;
      $y 2.0 isa length;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $x isa length;
      """
    Then answer size is: 1


  Scenario Outline: a '<type>' inserted as [<insert>] is retrieved when matching [<match>]
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define <attr> sub attribute, value <type>, owns ref @key;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    When get answers of graql insert
      """
      insert $x <insert> isa <attr>, has ref 0;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When concept identifiers are
      |     | check | value |
      | RF0 | key   | ref:0 |
    Then uniquely identify answer concepts
      | x   |
      | RF0 |
    When get answers of graql query
      """
      match $x <match> isa <attr>;
      """
    Then uniquely identify answer concepts
      | x   |
      | RF0 |

    Examples:
      | type     | attr       | insert           | match            |
      | long     | shoe-size  | 92               | 92               |
      | long     | shoe-size  | 92               | 92.00            |
      | double   | length     | 52               | 52               |
      | double   | length     | 52               | 52.00            |
      | double   | length     | 52.0             | 52               |
      | double   | length     | 52.0             | 52.00            |
      | datetime | start-date | 2019-12-26       | 2019-12-26       |
      | datetime | start-date | 2019-12-26       | 2019-12-26T00:00 |
      | datetime | start-date | 2019-12-26T00:00 | 2019-12-26       |
      | datetime | start-date | 2019-12-26T00:00 | 2019-12-26T00:00 |


  Scenario Outline: inserting [<value>] as a '<type>' throws an error
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define <attr> sub attribute, value <type>, owns ref @key;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    Then graql insert; throws exception
      """
      insert $x <value> isa <attr>, has ref 0;
      """
    Then the integrity is validated

    Examples:
      | type     | attr       | value        |
      | string   | colour     | 92           |
      | string   | colour     | 92.8         |
      | string   | colour     | false        |
      | string   | colour     | 2019-12-26   |
      | long     | shoe-size  | 28.5         |
      | long     | shoe-size  | "28"         |
      | long     | shoe-size  | true         |
      | long     | shoe-size  | 2019-12-26   |
      | long     | shoe-size  | 28.0         |
      | double   | length     | "28.0"       |
      | double   | length     | false        |
      | double   | length     | 2019-12-26   |
      | boolean  | is-alive   | 3            |
      | boolean  | is-alive   | -17.9        |
      | boolean  | is-alive   | 2019-12-26   |
      | boolean  | is-alive   | 1            |
      | boolean  | is-alive   | 0.0          |
      | boolean  | is-alive   | "true"       |
      | boolean  | is-alive   | "not true"   |
      | datetime | start-date | 1992         |
      | datetime | start-date | 3.14         |
      | datetime | start-date | false        |
      | datetime | start-date | "2019-12-26" |


  Scenario: when inserting an attribute, the type and value can be specified in two individual statements
    When get answers of graql insert
      """
      insert
      $x isa age;
      $x 10;
      """
    Then transaction commits
    When concept identifiers are
      |     | check | value  |
      | A10 | value | age:10 |
    Then uniquely identify answer concepts
      | x   |
      | A10 |
    Then the integrity is validated


  Scenario: inserting an attribute with no value throws an error
    Then graql insert; throws exception
      """
      insert $x isa age;
      """
    Then the integrity is validated


  Scenario: inserting an attribute value with no type throws an error
    Then graql insert; throws exception
      """
      insert $x 18;
      """
    Then the integrity is validated


  Scenario: inserting an attribute with a predicate throws an error
    Then graql insert; throws exception
      """
      insert $x > 18 isa age;
      """
    Then the integrity is validated


  ########
  # KEYS #
  ########

  Scenario: a thing can be inserted with a key
    When graql insert
      """
      insert $x isa person, has ref 0;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $x isa person;
      """
    When concept identifiers are
      |     | check | value |
      | PER | key   | ref:0 |
    Then uniquely identify answer concepts
      | x   |
      | PER |


  Scenario: when a type has a key, attempting to insert it without that key throws on commit
    When graql insert
      """
      insert $x isa person;
      """
    Then transaction commits; throws exception
    Then the integrity is validated


  Scenario: inserting two distinct values of the same key on a thing throws an error
    Then graql insert; throws exception
      """
      insert $x isa person, has ref 0, has ref 1;
      """
    Then the integrity is validated


  Scenario: instances of a key must be unique among all instances of a type
    Then graql insert; throws exception
      """
      insert
      $x isa person, has ref 0;
      $y isa person, has ref 0;
      """
    Then the integrity is validated


  Scenario: an error is thrown when inserting a second key on an attribute that already has one
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      name owns ref @key;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    When graql insert
      """
      insert $a "john" isa name, has ref 0;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    Then graql insert; throws exception
      """
      insert $a "john" isa name, has ref 1;
      """
    Then the integrity is validated


  ###########################
  # ANSWERS OF INSERT QUERY #
  ###########################

  Scenario: an insert with multiple thing variables returns a single answer that contains them all
    When get answers of graql insert
      """
      insert
      $x isa person, has name "Bruce Wayne", has ref 0;
      $z isa company, has name "Wayne Enterprises", has ref 0;
      """
    Then the integrity is validated
    When concept identifiers are
      |     | check | value |
      | BRU | key   | ref:0 |
      | WAY | key   | ref:0 |
    Then uniquely identify answer concepts
      | x   | z   |
      | BRU | WAY |


  Scenario: when inserting a thing variable with a type variable, the answer contains both variables
    When get answers of graql insert
      """
      match
        $type type company;
      insert
        $x isa $type, has name "Microsoft", has ref 0;
      """
    Then the integrity is validated
    When concept identifiers are
      |     | check | value   |
      | MIC | key   | ref:0   |
      | COM | label | company |
    Then uniquely identify answer concepts
      | x   | type |
      | MIC | COM  |


  ################
  # MATCH-INSERT #
  ################

  Scenario: match-insert triggers one insert per answer of the match clause
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      language sub entity, owns name, owns is-cool, owns ref @key;
      is-cool sub attribute, value boolean;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    Given graql insert
      """
      insert
      $x isa language, has name "Norwegian", has ref 0;
      $y isa language, has name "Danish", has ref 1;
      """
    Given transaction commits
    Given the integrity is validated
    Given session opens transaction of type: write
    When graql insert
      """
      match
        $x isa language;
      insert
        $x has is-cool true;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $x has is-cool true;
      """
    When concept identifiers are
      |     | check | value |
      | NOR | key   | ref:0 |
      | DAN | key   | ref:1 |


  Scenario: the answers of a match-insert only include the variables referenced in the 'insert' block
    Given graql insert
      """
      insert
      $x isa person, has name "Eric", has ref 0;
      $y isa company, has name "Microsoft", has ref 1;
      $r (employee: $x, employer: $y) isa employment, has ref 2;
      $z isa person, has name "Tarja", has ref 3;
      """
    Given transaction commits
    Given the integrity is validated
    When session opens transaction of type: write
    When get answers of graql insert
      """
      match
        (employer: $x, employee: $z) isa employment, has ref $ref;
        $y isa person, has name "Tarja";
      insert
        (employer: $x, employee: $y) isa employment, has ref 10;
      """
    Then the integrity is validated
    When concept identifiers are
      |     | check | value |
      | MIC | key   | ref:1 |
      | TAR | key   | ref:3 |
    # Should only contain variables mentioned in the insert (so excludes '$z')
    Then uniquely identify answer concepts
      | x   | y   |
      | MIC | TAR |


  Scenario: match-insert can take an attribute's value and copy it to an attribute of a different type
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      height sub attribute, value long;
      person owns height;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    Given graql insert
      """
      insert
      $x isa person, has name "Susie", has age 16, has ref 0;
      $y isa person, has name "Donald", has age 25, has ref 1;
      $z isa person, has name "Ralph", has age 18, has ref 2;
      """
    Given transaction commits
    Given the integrity is validated
    Given session opens transaction of type: write
    Given graql insert
      """
      match
        $x isa person, has age 16;
      insert
        $x has height 16;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match
        $x has height $z;
      get $x;
      """
    When concept identifiers are
      |     | check | value |
      | SUS | key   | ref:0 |
    Then uniquely identify answer concepts
      | x   |
      | SUS |


  Scenario: if match-insert matches nothing, then nothing is inserted
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      season-ticket-ownership sub relation, relates holder;
      person plays season-ticket-ownership:holder;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    Given get answers of graql query
      """
      match $p isa person;
      """
    Given answer size is: 0
    When graql insert
      """
      match
        $p isa person;
      insert
        $r (holder: $p) isa season-ticket-ownership;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $r isa season-ticket-ownership;
      """
    Then answer size is: 0


  Scenario: match-inserting only existing entities is a no-op
    Given get answers of graql insert
      """
      insert
      $x isa person, has name "Rebecca", has ref 0;
      $y isa person, has name "Steven", has ref 1;
      $z isa person, has name "Theresa", has ref 2;
      """
    Given concept identifiers are
      |     | check | value |
      | BEC | key   | ref:0 |
      | STE | key   | ref:1 |
      | THE | key   | ref:2 |
    Given uniquely identify answer concepts
      | x   | y   | z   |
      | BEC | STE | THE |
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    Given get answers of graql query
      """
      match $x isa person;
      """
    Given uniquely identify answer concepts
      | x   |
      | BEC |
      | STE |
      | THE |
    When graql insert
      """
      match
        $x isa person;
      insert
        $x isa person;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $x isa person;
      """
    Then uniquely identify answer concepts
      | x   |
      | BEC |
      | STE |
      | THE |


  Scenario: match-inserting only existing relations is a no-op
    Given get answers of graql insert
      """
      insert
      $x isa person, has name "Homer", has ref 0;
      $y isa person, has name "Burns", has ref 1;
      $z isa person, has name "Smithers", has ref 2;
      $c isa company, has name "Springfield Nuclear Power Plant", has ref 3;
      $xr (employee: $x, employer: $c) isa employment, has ref 4;
      $yr (employee: $y, employer: $c) isa employment, has ref 5;
      $zr (employee: $z, employer: $c) isa employment, has ref 6;
      """
    Given concept identifiers are
      |      | check | value |
      | HOM  | key   | ref:0 |
      | BUR  | key   | ref:1 |
      | SMI  | key   | ref:2 |
      | NPP  | key   | ref:3 |
      | eHOM | key   | ref:4 |
      | eBUR | key   | ref:5 |
      | eSMI | key   | ref:6 |
    Given uniquely identify answer concepts
      | x   | y   | z   | c   | xr   | yr   | zr   |
      | HOM | BUR | SMI | NPP | eHOM | eBUR | eSMI |
    Given transaction commits
    Given the integrity is validated
    Given session opens transaction of type: write
    Given get answers of graql query
      """
      match $r (employee: $x, employer: $c) isa employment;
      """
    Given uniquely identify answer concepts
      | r    | x   | c   |
      | eHOM | HOM | NPP |
      | eBUR | BUR | NPP |
      | eSMI | SMI | NPP |
    When graql insert
      """
      match
        $x isa employment;
      insert
        $x isa employment;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When get answers of graql query
      """
      match $r (employee: $x, employer: $c) isa employment;
      """
    Then uniquely identify answer concepts
      | r    | x   | c   |
      | eHOM | HOM | NPP |
      | eBUR | BUR | NPP |
      | eSMI | SMI | NPP |


  Scenario: match-inserting only existing attributes is a no-op
    Given get answers of graql insert
      """
      insert
      $x "Ash" isa name;
      $y "Misty" isa name;
      $z "Brock" isa name;
      """
    Given concept identifiers are
      |     | check | value      |
      | ASH | value | name:Ash   |
      | MIS | value | name:Misty |
      | BRO | value | name:Brock |
    Given uniquely identify answer concepts
      | x   | y   | z   |
      | ASH | MIS | BRO |
    Given transaction commits
    Given the integrity is validated
    Given session opens transaction of type: write
    Given get answers of graql query
      """
      match $x isa name;
      """
    Given uniquely identify answer concepts
      | x   |
      | ASH |
      | MIS |
      | BRO |
    When graql insert
      """
      match
        $x isa name;
      insert
        $x isa name;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When get answers of graql query
      """
      match $x isa name;
      """
    Then uniquely identify answer concepts
      | x   |
      | ASH |
      | MIS |
      | BRO |


  Scenario: re-inserting a matched instance does nothing
    Given graql insert
      """
      insert
      $x isa person, has ref 0;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    Then graql insert
      """
      match
        $x isa person;
      insert
        $x isa person;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $x isa person;
      """
    Then answer size is: 1


  Scenario: re-inserting a matched instance as an unrelated type throws an error
    Given graql insert
      """
      insert
      $x isa person, has ref 0;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    Then graql insert; throws exception
      """
      match
        $x isa person;
      insert
        $x isa company;
      """
    Then the integrity is validated


  Scenario: inserting a new type on an existing instance has no effect, if the old type is a subtype of the new one
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define child sub person;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    Given graql insert
      """
      insert $x isa child, has ref 0;
      """
    Given transaction commits
    Given the integrity is validated
    Given session opens transaction of type: write
    When graql insert
      """
      match
        $x isa child;
      insert
        $x isa person;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $x isa! child;
      """
    Then answer size is: 1
    When get answers of graql query
      """
      match $x isa! person;
      """
    Then answer size is: 0


  #####################################
  # MATERIALISATION OF INFERRED FACTS #
  #####################################

  # Note: These tests have been placed here because Resolution Testing was not built to handle these kinds of cases

  Scenario: when inserting a thing that has inferred concepts, those concepts are not automatically materialised
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      person owns score;
      score sub attribute, value double;
      rule ganesh-rule:
      when {
        $x isa person, has score $s;
        $s > 0.0;
      } then {
        $x has name "Ganesh";
      };
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    Given graql insert
      """
      insert
      $x isa person, has ref 0, has score 1.0;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When concept identifiers are
      |     | check | value       |
      | GAN | value | name:Ganesh |
    When get answers of graql query
      """
      match $x isa name;
      """
    Then uniquely identify answer concepts
      | x   |
      | GAN |
    When graql delete
      """
      match
        $x isa person;
      delete
        $x isa person;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $x isa name;
      """
    # If the name 'Ganesh' had been materialised, then it would still exist in the knowledge graph.
    Then answer size is: 0


  Scenario: when inserting a thing with an inferred attribute ownership, the ownership is not automatically persisted
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      person owns score;
      score sub attribute, value double;
      rule copy-scores-to-all-people:
      when {
        $x isa person, has score $s;
        $y isa person;
        $x != $y;
      } then {
        $y has score $s;
      };
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    Given graql insert
      """
      insert
      $x isa person, has ref 0, has name "Chris", has score 10.0;
      $y isa person, has ref 1, has name "Freya";
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When concept identifiers are
      |     | check | value      |
      | CHR | key   | ref:0      |
      | FRE | key   | ref:1      |
      | TEN | value | score:10.0 |
    When get answers of graql query
      """
      match $x isa person, has score $score;
      """
    Then uniquely identify answer concepts
      | x   | score |
      | CHR | TEN   |
      | FRE | TEN   |
    When graql delete
      """
      match
        $x isa person, has name "Chris";
      delete
        $x isa person;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $x isa score;
      """
    # The score '10.0' still exists, we never deleted it
    Then uniquely identify answer concepts
      | x   |
      | TEN |
    When get answers of graql query
      """
      match $x isa person, has score $score;
      """
    # But Freya's ownership of score 10.0 was never materialised and is now gone
    Then answer size is: 0


  Scenario: when inserting things connected to an inferred attribute, the inferred attribute gets materialised

  By explicitly inserting (x,y) is a relation, we are making explicit the fact that x and y both exist.

    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define

      name-initial sub relation,
        relates lettered-name,
        relates initial;

      score sub attribute, value double;
      letter sub attribute, value string,
        plays name-initial:initial;

      name plays name-initial:lettered-name;
      person owns score;

      rule ganesh-rule:
      when {
        $x isa person, has score $s;
        $s > 0.0;
      } then {
        $x has name "Ganesh";
      };
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    Given graql insert
      """
      insert
      $x isa person, has ref 0, has score 1.0;
      $y 'G' isa letter;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When concept identifiers are
      |     | check | value       |
      | GAN | value | name:Ganesh |
      | G   | value | letter:G    |
    When get answers of graql query
      """
      match $x isa name;
      """
    Then uniquely identify answer concepts
      | x   |
      | GAN |
    # At this step we materialise the inferred name 'Ganesh' because the material name-initial relation depends on it.
    When graql insert
      """
      match
        $p isa person, has name $x;
        $x 'Ganesh' isa name;
        $y 'G' isa letter;
      insert
        (lettered-name: $x, initial: $y) isa name-initial;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When graql delete
      """
      match
        $x isa person;
      delete
        $x isa person;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $x isa person;
      """
    Then answer size is: 0
    When get answers of graql query
      """
      match $x isa name;
      """
    # We deleted the person called 'Ganesh', but the name still exists because it was materialised on match-insert
    Then uniquely identify answer concepts
      | x   |
      | GAN |
    When get answers of graql query
      """
      match (lettered-name: $x, initial: $y) isa name-initial;
      """
    # And the inserted relation still exists too
    Then uniquely identify answer concepts
      | x   | y |
      | GAN | G |


  Scenario: when inserting things connected to an inferred relation, the inferred relation gets materialised
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql undefine
      """
      undefine
      employment owns ref;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    Given graql define
      """
      define

      contract sub entity,
        plays employment-contract:contract;

      employment-contract sub relation,
        relates employment,
        relates contract;

      employment plays employment-contract:employment;

      rule henry-is-employed:
      when {
        $x isa person, has name "Henry";
      } then {
        (employee: $x) isa employment;
      };
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    Given graql insert
      """
      insert
      $x isa person, has name "Henry", has ref 0;
      $c isa contract;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When get answers of graql query
      """
      match $x isa employment;
      """
    Then answer size is: 1
    # At this step we materialise the inferred employment because the material employment-contract depends on it.
    When graql insert
      """
      match
        $e isa employment;
        $c isa contract;
      insert
        (employment: $e, contract: $c) isa employment-contract;
      """
    Then transaction commits
    Then the integrity is validated
    When connection close all sessions
    When connection open schema session for database: grakn
    When session opens transaction of type: write
    When graql undefine
      """
      undefine
      rule henry-is-employed;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $x isa employment;
      """
    # We deleted the rule that infers the employment, but it still exists because it was materialised on match-insert
    Then answer size is: 1
    When get answers of graql query
      """
      match (contracted: $x, contract: $y) isa employment-contract;
      """
    # And the inserted relation still exists too
    Then answer size is: 1


  Scenario: when inserting things connected to a chain of inferred concepts, the whole chain is materialised
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define

      vertex sub entity,
        owns index @key,
        plays link:coordinate,
        plays reachable:coordinate;

      link sub relation, relates coordinate;

      reachable sub relation,
        relates coordinate,
        plays road-proposal:connected-path;

      road-proposal sub relation,
        relates connected-path,
        plays road-construction:proposal-to-construct;

      road-construction sub relation, relates proposal-to-construct;

      index sub attribute, value string;

      rule a-linked-point-is-reachable:
      when {
        ($x, $y) isa link;
      } then {
        (coordinate: $x, coordinate: $y) isa reachable;
      };

      rule a-point-reachable-from-a-linked-point-is-reachable:
      when {
        ($x, $z) isa link;
        ($z, $y) isa reachable;
      } then {
        (coordinate: $x, coordinate: $y) isa reachable;
      };

      rule propose-roads-between-reachable-points:
      when {
        $r isa reachable;
      } then {
        ($r) isa road-proposal;
      };
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    Given graql insert
      """
      insert

      $a isa vertex, has index "a";
      $b isa vertex, has index "b";
      $c isa vertex, has index "c";
      $d isa vertex, has index "d";

      (coordinate: $a, coordinate: $b) isa link;
      (coordinate: $b, coordinate: $c) isa link;
      (coordinate: $c, coordinate: $c) isa link;
      (coordinate: $c, coordinate: $d) isa link;
      """
    Given transaction commits
    Given the integrity is validated
    Given session opens transaction of type: write
    When graql insert
      """
      match
        $a isa vertex, has index "a";
        $d isa vertex, has index "d";
        $reach ($a, $d) isa reachable;
        $r ($reach) isa road-proposal;
      insert
        (proposal-to-construct: $r) isa road-construction;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When graql delete
      """
      match
        $r (coordinate: $c) isa link;
        $c isa vertex, has index "c";
      delete
        $r isa link;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    # After deleting all the links to 'c', our rules no longer infer that 'd' is reachable from 'a'. But in fact we
    # materialised this reachable link when we did our match-insert, because it played a role in our road-proposal,
    # which itself plays a role in the road-construction that we explicitly inserted:
    When get answers of graql query
      """
      match
        $a isa vertex, has index "a";
        $d isa vertex, has index "d";
        $reach ($a, $d) isa reachable;
      """
    Then answer size is: 1
    # On the other hand, the fact that 'c' was reachable from 'a' was not -directly- used; although it was needed
    # in order to infer that (a,d) was reachable, it did not, itself, play a role in any relation that we materialised,
    # so it is now gone.
    When get answers of graql query
      """
      match
        $a isa vertex, has index "a";
        $c isa vertex, has index "c";
        $reach ($a, $c) isa reachable;
      """
    Then answer size is: 0


  Scenario: when matching two types and inserting one of them, the number of entities of that type doubles each time
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql undefine
      """
      undefine
      person owns ref;
      company owns ref;
      employment owns ref;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    Given graql insert
      """
      insert
      $x isa person;
      $y isa company;
      """
    Given transaction commits
    Given the integrity is validated
    Given session opens transaction of type: write
    When graql insert
      """
      match
        $x isa person;
        $y isa company;
      insert
        $z isa person;
        (employee: $z, employer: $y) isa employment;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When graql insert
      """
      match
        $x isa person;
        $y isa company;
      insert
        $z isa person;
        (employee: $z, employer: $y) isa employment;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When graql insert
      """
      match
        $x isa person;
        $y isa company;
      insert
        $z isa person;
        (employee: $z, employer: $y) isa employment;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When graql insert
      """
      match
        $x isa person;
        $y isa company;
      insert
        $z isa person;
        (employee: $z, employer: $y) isa employment;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When graql insert
      """
      match
        $x isa person;
        $y isa company;
      insert
        $z isa person;
        (employee: $z, employer: $y) isa employment;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When graql insert
      """
      match
        $x isa person;
        $y isa company;
      insert
        $z isa person;
        (employee: $z, employer: $y) isa employment;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $x isa person;
      """
    Then answer size is: 64
    When get answers of graql query
      """
      match $x isa employment;
      """
    # The original person is still unemployed.
    Then answer size is: 63


  Scenario: match-insert can be used to repeatedly duplicate all entities
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql undefine
      """
      undefine person owns ref;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    Given graql insert
      """
      insert $x isa person;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When graql insert
      """
      match $x isa person; insert $z isa person;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When graql insert
      """
      match $x isa person; insert $z isa person;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When graql insert
      """
      match $x isa person; insert $z isa person;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When graql insert
      """
      match $x isa person; insert $z isa person;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When graql insert
      """
      match $x isa person; insert $z isa person;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: write
    When graql insert
      """
      match $x isa person; insert $z isa person;
      """
    Then transaction commits
    Then the integrity is validated
    When session opens transaction of type: read
    Then the integrity is validated
    When get answers of graql query
      """
      match $x isa person;
      """
    Then answer size is: 64


  ####################
  # TRANSACTIONALITY #
  ####################

  Scenario: if any insert in a transaction fails with a syntax error, none of the inserts are performed
    Given graql insert
      """
      insert
      $x isa person, has name "Derek", has ref 0;
      """
    When graql insert; throws exception
      """
      insert
      $y qwertyuiop;
      """
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $x isa person, has name "Derek";
      """
    Then answer size is: 0


  Scenario: if any insert in a transaction fails with a semantic error, none of the inserts are performed
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      capacity sub attribute, value long;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    Given session opens transaction of type: write
    Given graql insert
      """
      insert
      $x isa person, has name "Derek", has ref 0;
      """
    When graql insert; throws exception
      """
      insert
      $y isa person, has name "Emily", has capacity 1000;
      """
    Then the integrity is validated
    When get answers of graql query
      """
      match $x isa person, has name "Derek";
      """
    Then answer size is: 0


  Scenario: if any insert in a transaction fails with a 'key' violation, none of the inserts are performed
    Given graql insert
      """
      insert
      $x isa person, has name "Derek", has ref 0;
      """
    When graql insert; throws exception
      """
      insert
      $y isa person, has name "Emily", has ref 0;
      """
    Then the integrity is validated
    When session opens transaction of type: read
    When get answers of graql query
      """
      match $x isa person, has name "Derek";
      """
    Then answer size is: 0


  ##############
  # EDGE CASES #
  ##############

  Scenario: the 'iid' property is used internally by Grakn and cannot be manually assigned
    Given connection close all sessions
    Given connection open schema session for database: grakn
    Given session opens transaction of type: write
    Given graql define
      """
      define
      bird sub entity;
      """
    Given transaction commits
    Given the integrity is validated
    Given connection close all sessions
    Given connection open data session for database: grakn
    When session opens transaction of type: write
    Then graql insert; throws exception
      """
      insert
      $x isa bird;
      $x iid V123;
      """
    Then the integrity is validated
