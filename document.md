% Title = "Integrity protection for vCard and iCalendar"
% abbrev = "calconnect-vcard-icalendar-integrity"
% category = "std"
% docName = "draft-calconnect-vcard-icalendar-integrity"
% updates = [5545, 6321, 6350, 6351]
% ipr= "trust200902"
% area = "Internet"
% workgroup = "Network Working Group"
%
% date = 2017-02-15T00:00:00Z
%
% [[author]]
% initials = "R. H."
% surname = "Tse"
% fullname = "Ronald Henry Tse"
% organization = "Ribose"
%  [author.address]
%  email = "ronald.tse@ribose.com"
%  uri = "https://www.ribose.com"
%   [author.address.postal]
%   street = "Suite 1111, 1 Pedder Street"
%   city = "Central"
%   region = "Hong Kong"
%   country = "Hong Kong"
%
% [[author]]
% initials="P."
% surname="Tam"
% fullname="Peter Kwan Yu Tam"
% organization = "Ribose"
%  [author.address]
%  email = "peter.tam@ribose.com"
%  uri = "https://www.ribose.com"
%   [author.address.postal]
%   street = "Suite 1111, 1 Pedder Street"
%   city = "Central"
%   region = "Hong Kong"
%   country = "Hong Kong"
%
% [[author]]
% initials="E."
% surname="Borsboom"
% fullname="Erick Borsboom"
% organization = "Ribose"
%  [author.address]
%  email = "erick.borsboom@ribose.com"
%  uri = "https://www.ribose.com"
%   [author.address.postal]
%   street = "Suite 1111, 1 Pedder Street"
%   city = "Central"
%   region = "Hong Kong"
%   country = "Hong Kong"

.# Abstract

This document specifies an integrity checking mechanism and related
properties for:

* vCard version 4 (vCard v4) [@!RFC6350]; and
* iCalendar (Internet Calendaring and Scheduling Core Object
  Specification) [@!RFC5545]

{mainmatter}


#  TODOs

* Add CalDAV mechanisms and recommendations
* Fill in missing example hashes
* Consider adding non-standardized PQCrypto algorithms


#  Introduction {#introduction}

The ubiquitous vCard and iCalendar standards, also known together as the
"VCOMPONENT" or "vObject" family of standards, powers digital contact
exchanges, calendaring and scheduling on over 2.5 billion devices today.

Integrity [@RFC3552 2.1.2.] is a key property of "information security"
defined as the "preservation of confidentiality, integrity and
availability of information" [@ISO-IEC-27000 2.33]. When provided with
a VCOMPONENT, however, there is no inherent method to detect its own
data integrity.

In reality, people are known to exchange vCard and iCalendar data
through unreliable means, which could affect data integrity during
transport, such as Internet mail [@RFC0822] and QR Codes
[@ISO-IEC-18004]. On the other hand, there are implementations that
store vCard and/or iCalendar content on disk, which could be subject to
silent corruption.

Previous standards were created in a time where integrity concerns were
less widespread, and relied solely on data transport, application and
storage integrity without considering on whether the content
transmitted, processed or retrieved was as intended without corruption.

This document specifically deals with information integrity in face of
the following risks:

* VCOMPONENTs on storage may face silent corruption;
* VCOMPONENTs transmitted over networks or other channels may face
  network corruption that may go undetected by the underlying transport
  mechanism.

The standards subject to such risks include:

* vCard version 2.1 [@!vCard21];
* vCard version 3 [@!RFC2425], [@!RFC2426];
* vCard version 4 [@!RFC6350]; and
* iCalendar [@!RFC5545].


<!-- TODO: add iCalendar formats-->

This document provides:

* a stable mechanism to calculate VCOMPONENT equivalence using
  cryptographic hash functions, valid across alternative
  representations, such as xCard/jCard and xCal/jCal;
* introduces a new property CHECKSUM to VCOMPONENTs;
* usage of the CHECKSUM property on CardDAV [@!RFC6352] and CalDAV
  [@!RFC4791] systems;
* alternative representations of the CHECKSUM property for xCard
  [@!RFC6351], jCard [@!RFC7095], xCal [@!RFC6321] and jCal [@!RFC7265]
  representations of this property; and
* guidance to implementers on dealing with integrity concerns and the
  proper usage of CHECKSUM.

This work is produced by the CalConnect TC-VCARD committee
[@CALCONNECT-VCARD] as the first in a series of VCOMPONENT security
enhancements. The decision to update the existing vCard version 4
[@RFC6350] and iCalendar standards were chosen to maintain maximum
backwards compatibility.


#  Conventions and Terminology

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**",
"**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**",
"**MAY**", and "**OPTIONAL**" in this document are to be interpreted
as described in RFC 2119 [@!RFC2119].

All definitions from [@!RFC6350] are inherited in this document except
when explicitly overridden.

##  Definitions

VCOMPONENT, vObject
: the vCard component (VCARD) and iCalendar (VCALENDAR) component

Client User Application (CUA)
: the VCOMPONENT client implementation that interfaces with
  the user


#  Properties

Property cardinalities are indicated in the same method as provided by
[@!RFC6350] based on ABNF [@!RFC5234 Section 3.6].


##  CHECKSUM {#property_checksum}

These registration details for the CHECKSUM property adhere to rules
specified in [@!RFC6350] Section 10.2.1.


Namespace:

Property name:
  CHECKSUM

Purpose:
  Allows content integrity detection and verification against
  data corruption of a VCOMPONENT.

Value type:
  A single text value.

Cardinality:
  \*

Property parameters:
  HASHA, HASHP

Value:
  text

Description:
  CHECKSUM is an **OPTIONAL** property of a VCOMPONENT. There can be
  multiple CHECKSUM properties within the same VCOMPONENT. VCOMPONENT
  client implementations are **RECOMMENDED** to implement CHECKSUM for a
  basic level of integrity guarantee.

  The CHECKSUM value used to compare the checksum of data should be
  selected in this way:

  * the highest PREF value among all CHECKSUM properties; then
  * the most applicable HASHA algorithm taking into account collision
    resistance and application support.

Format definition:
  ABNF:

    CHECKSUM-param =  "VALUE=text"
    CHECKSUM-param =  pid-param / pref-param / altid-param /
                      checksum-param-hasha / checksum-param-hashp /
                      iana-token

    CHECKSUM-value = TEXT
      ; Value type and VALUE parameter MUST match.


Example(s):
  See [](#property_checksum_examples)


### Examples {#property_checksum_examples}

```
CHECKSUM:
  ad58ca4f14b317dea48987f4991bdcd56fdf0f6a95049623f0fe5c4453d157e0

CHECKSUM;PREF=99:
  3ac0e03cccda6663ed32052749cc5c607d88e381f9cfcb795317bc39a57909e3

CHECKSUM;HASHA=sha224:
  22e92efac9d7b0e63695a9d960376ace1e69eb317e3d42c5c94f1401
```


#  Property Parameters {#property_parameters}

The CHECKSUM allowed property parameters of `PID`, `PREF`, `ALTID`
have the same meaning as on other properties [@RFC6350].


##  PREF Property Parameter

The `PREF` property parameter indicates the preference of the vCard
author on which CHECKSUM value to put most weight on.

Usage of this parameter is further explained in
[](#checksum_validation).


##  HASHA Property Parameter {#parameter_hasha}

Registration details for the HASHA property parameter adhere to rules
specified in [@!RFC6350] Section 10.2.1.

Namespace:

Parameter name:
  HASHA

Purpose:
  Specify the hash function used for the property value

Description:
  Possible values are defined in [](#vc_hash_function_registry).

  The HASHA Property Parameter **MUST** not be applied on properties
  other than CHECKSUM unless specified.

  New HASHA hash functions **MUST** be specified in a Standards Track
  RFC.

Format definition:
  ABNF:

  ```
    hasha-param = "HASHA=" hasha-value *("," hasha-value)

    hasha-value = "sha3-256" / iana-token / x-name
    ; This is further defined in [](#checksum_functions)
  ```


Example(s):
  ```
    CHECKSUM;HASHA=sha384:
      4055b176af753e251bc269007569c8f9633e6227a5f9727381cfba0bbb44a0c9
      25b8d31d72083d9cb4dc1da278f3a4e4


    CHECKSUM;HASHA=streebog256:
      TODO
  ```




##  HASHP Property Parameter {#parameter_hashp}

Certain hash functions such as extendable output functions (XOFs) can be
customized:

* SHAKE-128, SHAKE-256, cSHAKE-128, cSHAKE256, ParallelHash128,
  ParallelHash256 support customizable hash value length.
* cSHAKE-128, cSHAKE-256, support function name customization.
* cSHAKE-128, cSHAKE-256, ParallelHash128, ParallelHash256 support
  customizable bit strings.
* ParallelHash128, ParallelHash256 support customizable block sizes for
  parallel hashing.

Since each hash function may take different specifiers, each hash
function identifier **MAY** specify its own set of HASHP specifiers in a
particular order. The parameter value(s) entered **MUST** conform to the
hash function's specification in a Standards Track RFC. An
implementation **MUST** follow the value type interpretation specified
for the hash function.

For example, in [](#supported_table), the cSHAKE-128 algorithm (with the
identifier `cshake128`) takes `(L, N, S)` as input, where L is an
integer to specify the output bit length, N is a text string
representing the function name, S is a text string for customization
purposes. When given a HASHP parameter value "512,address book,Orange",
for the HASHA identifier `cshake128`, the implementation **MUST**
recognize that L is the integer 512, N is the string "address book", and
S is the string "Orange".


Registration details for the HASHP property parameter adhere to rules
specified in [@!RFC6350] Section 10.2.1.

Namespace:

Parameter name:
  HASHP

Purpose:
  Describe hash function specifiers used for the property value.

Description:
  Provide specifiers for the HASHA hash function used to calculate the
  property value.

  Possible values are defined in [](#vc_hash_function_specifier_registry).

  The HASHP Property Parameter **MUST** not be applied on properties
  other than CHECKSUM unless specified.


Format definition:
  ABNF:

  ```
    hashp-param = "HASHP=" hashp-value *("," hashp-value)

    hashp-value = param-value
    ; This list of values must be specified in the exact order and value
      type defined in [](#supported_table)
  ```

Example(s):
  ```
    CHECKSUM;HASHA=shake128;HASHP=512,"Directory Service Identifier":
      TODO

    CHECKSUM;HASHA=parallelhash128;HASHP=64,512:
      TODO
  ```


#  Hash Functions {#checksum_functions}

The CHECKSUM value is calculated by a chosen cryptographic hash function
specified in the HASHA property parameter. Certain hash functions accept
customization specifiers, which can be specified in the HASHP property
parameter.


##  Supported Hash Functions And Their Specifiers {#supported_table}

CHECKSUM supports the following hash algorithms in the following table.

Algorithms with no specifiers:

Algorithm | Identifier | Message Digest Size (bits) | Description
:-:|:-:|:-:|:-:
SHA-2 SHA-224 | sha224 | 224 | [@!RFC6234]; [@!NIST-FIPS-180-4]; [@!ISO-IEC-10118-3] Dedicated Hash-Function 8 (SHA-224)
SHA-2 SHA-256 | sha256 | 256 | [@!RFC6234]; [@!NIST-FIPS-180-4]; [@!ISO-IEC-10118-3] Dedicated Hash-Function 4 (SHA-256)
SHA-2 SHA-384 | sha384 | 384 | [@!RFC6234]; [@!NIST-FIPS-180-4]; [@!ISO-IEC-10118-3] Dedicated Hash-Function 6 (SHA-384)
SHA-2 SHA-512 | sha512 | 512 | [@!RFC6234]; [@!NIST-FIPS-180-4]; [@!ISO-IEC-10118-3] Dedicated Hash-Function 5 (SHA-512)
SHA-2 SHA-512/224 | sha512-224 | 224 | [@!NIST-FIPS-180-4]; [@!ISO-IEC-10118-3] Dedicated Hash-Function 9 (SHA-512/224)
SHA-2 SHA-512/256 | sha512-256 | 256 | [@!NIST-FIPS-180-4]; [@!ISO-IEC-10118-3] Dedicated Hash-Function 10 (SHA-512/256)
WHIRLPOOL | whirlpool | 512 | [@!WHIRLPOOL]; [@!ISO-IEC-10118-3] Dedicated Hash-Function 7 (WHIRLPOOL)
STREEBOG-256 | streebog256 | 256 | [@!STREEBOG] GOST R 34.11-2012; [@!RFC6986]; [@!ISO-IEC-10118-3] Dedicated Hash-Function 12 (STREEBOG-256)
STREEBOG-512 | streebog512 | 512 | [@!STREEBOG] GOST R 34.11-2012; [@!RFC6986]; [@!ISO-IEC-10118-3] Dedicated Hash-Function 11 (STREEBOG-512)
SHA3-224 | sha3-224 | 224 | [@!NIST-FIPS-202]; [@!ISO-IEC-10118-3] Dedicated Hash-Function 13 (SHA3-224)
SHA3-256 | sha3-256 | 256 | [@!NIST-FIPS-202]; [@!ISO-IEC-10118-3] Dedicated Hash-Function 14 (SHA3-256)
SHA3-384 | sha3-384 | 384 | [@!NIST-FIPS-202]; [@!ISO-IEC-10118-3] Dedicated Hash-Function 15 (SHA3-384)
SHA3-512 | sha3-512 | 512 | [@!NIST-FIPS-202]; [@!ISO-IEC-10118-3] Dedicated Hash-Function 16 (SHA3-512)
SM3 | sm3 | 512 | [@?I-D.shen-sm3-hash]; [@!SM3]; [@!ISO-IEC-10118-3] Dedicated Hash-Function 17 (SM3)
IANA registered hash algorithm | iana-token | iana-token | IANA
Vendor-specific hash algorithm | x-token | Vendor specific | Vendor specific

Algorithms with specifiers:

Algorithm | Identifier | Message Digest Size (bits) | Specifier(s) | Description
:-:|:-:|:-:|:-:|:-:
SHAKE-128 | shake128 | Varys | L: integer (default: 256) | [@!NIST-FIPS-202]
SHAKE-256 | shake256 | Varys | L: integer (default: 512) | [@!NIST-FIPS-202]
cSHAKE-128 | cshake128 | Varys | L: integer (default: 256), N: text (default: ""), S: text (default: "") | [@!NIST-SP-800-185]
cSHAKE-256 | cshake256 | Varys | L: integer (default: 512), N: text (default: ""), S: text  (default: "")| [@!NIST-SP-800-185]
ParallelHash-128 | parallel128 | Varys | B: integer (default: 64), L: integer (default: 256), S: text (default: "") | [@!NIST-SP-800-185]
ParallelHash-256 | parallel256 | Varys | B: integer (default: 64), L: integer (default: 256), S: text (default: "") | [@!NIST-SP-800-185]
IANA registered hash algorithm | iana-token | iana-token | iana-token | IANA
Vendor-specific hash algorithm | x-token | Vendor specific | Vendor specific | Vendor specific

* The CHECKSUM value contains the output of the hash function, which
  is usually stored in hexadecimal format as the `text` value type.
* The identifier from this table should be put as value of the property
  parameter HASHA.
* Algorithms with a "Variable" message digest size mean its length can
  be specified by a HASHP specifier.


Example.

```
sha3-256('BEGIN:VCARD') = "f1fcbc9bddcd44b1e50db99a277bc868" +
                          "61736eb32cb30ef7e7a2c9ef95c05d50"
```

The default algorithm is ```sha3-256```.  An implementation that
supports this document **MUST** support at least the ```sha3-256```
function.



##  SHA-2 {#checksum_sha2}

Secure Hash Algorithm 2 (SHA-2) is a family of secure hash algorithms
defined in [@!NIST-FIPS-180-4]: SHA-224, SHA-256, SHA-384, SHA-512,
SHA-512/224 and SHA-512/256.

* SHA-256 and SHA-512 are the two core hash functions that differ by
  process parameters, which produce a hash value of 256 and 512 bits
  respectively.
* SHA-224 is identical to SHA-256, except that different initial hash
  values are used, and the final hash value is truncated to 224 bits.
* SHA-384, SHA-512/224, SHA-512/256 are identical to SHA-512, except
  that different initial hash values are used, and the final hash value is
  truncated to 384, 224, 256 bits respectively. In particular,
  SHA-512/224 and SHA-512/256 use initial hash values generated by the
  `SHA-512/t IV Generation Function` given in [@!NIST-FIPS-180-4].


## WHIRLPOOL {#checksum_whirlpool}

WHIRLPOOL is a hash function that operates on messages less than 2^256^
bits in length, and produces a hash value of 512 bits [@!WHIRLPOOL].

It uses Merkle-Damgård strengthening and the Miyaguchi-Preneel hashing
scheme with a dedicated 512-bit block cipher called $$W$$ [@!WHIRLPOOL].


## SM3 {#checksum_sm3}

SM3 is a hash function [@?I-D.shen-sm3-hash] standardized by the Chinese
Commercial Cryptography Administration Office [@!SM3] for the use of
electronic authentication service systems.

SM3 is an iterated hash function based on a Merkle-Damgård design,
processes on 512-bit input message blocks with a 256-bit state, and
produces a 256-bit hash value.


## SHA-3 {#checksum_sha3}

Secure Hash Algorithm-3 (SHA-3) is a family of hash functions defined in
[@!NIST-FIPS-202] consisting of:

* four cryptographic hash functions, SHA3-224, SHA3-256, SHA3-384,
  SHA3-512; and
* two extendable-output functions (XOFs), SHAKE128 and SHAKE256.

Each SHA-3 function is based on an instance of the KECCAK algorithm
[@KECCAK] which won the SHA-3 Cryptographic Hash Algorithm Competition
[@NIST-FIPS-202].

* SHA3-224, SHA3-256, SHA3-384, SHA3-512 produce a hash value output
  of 224, 256, 384 and 512 bits respectively.
* SHAKE128 and SHAKE256 are XOFs that produce output of arbitrary
  length, which can be specified using the "HASHP" property parameter.


Notes concerning SHA-3 based XOFs [@NIST-FIPS-202]:

* Output of a XOF can be considered as an infinite string, and the
  "HASHP" property parameter simply determines how many initial bits of
  the initial string to use.
* The SHAKE-256 and -128 functions, as long as at least 2x bits of their
  output is used, they have generic security strengths of 256 and 128
  bits. However, using an excess of 64 or 32 bytes of their output
  respectively, does not increase their collision-resistance.


## STREEBOG {#checksum_streebog}

Streebog (or Stribog) is a family of two separate hash functions defined
in the Russian standard GOST R 34.11-2012 [@STREEBOG] where the
functions differ in their output lengths, which are 256- and 512-bits
respectively.

Streebog accepts message block sizes of 512-bits, and both functions
only differ in the different IVs used other than the output length
[@STREEBOG].


## BLAKE2 {#checksum_blake2}

BLAKE2, described in [@!BLAKE2] and [@!RFC7693], is a hash algorithm
that comes in two flavors, BLAKE2b and BLAKE2s. It is the successor of
BLAKE [@!BLAKE] which was a NIST SHA-3 competition finalist.

* BLAKE2b is optimized for 64-bit platforms and produces hash values of
  any size between 1 and 64 bytes
* BLAKE2s is optimized for 8- to 32-bit platforms and produces hash
  values of any size between 1 and 32 bytes

While BLAKE2 allows customizing parameters, including salt and a
customization string, implementations that adhere to this specification
should adopt BLAKE2 as defined in [@!RFC7693].


## SHA-3 Extensions {#checksum_sha3_ext}

[@!NIST-SP-800-185] defines a number of additional hash algorithms based
on algorithms defined in [@!NIST-FIPS-202], including:

* cSHAKE-128, cSHAKE-256: customizable SHAKE functions, which take extra
  inputs of hash value length, a function name string, and a customization
  string;
* ParallelHash128, ParallelHash256: supports efficient hashing of very
  long strings by taking advantage of the parallelism available in modern
  processors based on SHAKE. These take the extra inputs of block size,
  hash value length and a customization string.

Both cSHAKE and ParallelHash are XOFs that can produce variable length
output. The number suffix at their names mean the security strength bits
of the algorithm.


<!-- TODO in the future ## BLAKE2X -->


# Hash Function Considerations

## Collision Resistance of Hash Function Families

For our purposes we specify the following strength families of hash
algorithms. Hash functions placed in the higher bracket are considered
"more resistant" in algorithm selection.

Strength | Hash Function Identifier
:-:|:-:
1 | sha224, sha256, sha384, sha512, sha512-224, sha512-256
2 | whirlpool, streebog256, streebog512
3 | blake2b256, blake2b384, blake2b512, blake2s224, blake2s256, sm3,
  | shake128, shake256, sha3-224, sha3-256, sha3-384, sha3-512


## Guidelines for Hash Function Selection

* Collision-resistance: higher bit length digests are generally
  preferable to lower bit length digests due to lower susceptibility to
  collisions.
* Performance: some hash functions are more computation intensive.
  Higher bit length digests generally require more computation to
  generate.
* History: a hash algorithm that has withstood cryptanalytic attacks
  provide better confidence than ones that have not been in widespread
  use.
* Availability and interoperability: certain hash algorithms, such as
  SHA-2 ([@!RFC6234]; [@!NIST-FIPS-180-4]; [@!ISO-IEC-10118-3] Dedicated
  Hash-Function 4 (SHA-256)), are more prevalently available on
  computing platforms.

Selection of the hash function should be based on a balance of
collision resistance, performance, history and interoperability.


## Hash Functions Considered Unsuitable

The following hash functions are specifically excluded due to stated
reasons:

* RIPEMD-160 [@ISO-IEC-10118-3] Dedicated Hash-Function 1 and
  RIPEMD-128 [@ISO-IEC-10118-3] Dedicated Hash-Function 2,
  are specifically excluded as they do no longer provide a sufficient
  level of collision resistance, see [@ISO-IEC-10118-3] Section 7.1 Note
  2 [@ISO-IEC-10118-3] Section 8.1 Note 2. The RIPEMD optional
  extensions RIPEMD-256 and RIPEMD-320 [@RIPEMD160] are also excluded as
  they are of the same security levels as RIPEMD-128 and RIPE-160
  respectively.

* SHA-1 [@RFC3174] [@ISO-IEC-10118-3] Dedicated Hash-Function 3 is
  excluded as it does not provide a sufficient level of collision
  resistance, see [@ISO-IEC-10118-3] Section 9.1 Note 2.

* CRC-32 [@ISO-IEC-13239] and in general CRC algorithms are excluded due
  to weak collision resistance.


<!-- Integrity calculation methods should not include other integrity
calculation methods inside. -->


#  Method of CHECKSUM Value Calculation

The following method to calculate CHECKSUM is devised for these desired
properties:

* Stable across alternative representation formats of the vCard and
  iCalendar, such as xCard/jCard.
* Allows comparison of equivalence of content rather than formatting.
  E.g., addition of new-lines within a vCard and order of listed
  properties do not affect the resulting checksum value.


For implementations that handle CHECKSUM, its calculation **MUST** be
performed after all property updates including REV, which is often
updated during save.

Steps to calculate CHECKSUM:

1. Calculate the hash value of the VCOMPONENT

  1. Determine the need to add a new CHECKSUM property.

     * If there is no existing CHECKSUM property, add it as the last
     property of the VCOMPONENT, with the selected cryptographic hash
     algorithm type and the selected hash parameters. Its value should
     be set to "" (empty string).

     * If there is an existing CHECKSUM property:

       * If its parameters are identical to the user's current settings
         (or the CUA's defaults), there is no need to add an extra
         CHECKSUM property. Set its value to "" (empty string).

       * Otherwise, add the extra CHECKSUM property as described above.

  1. Calculate hash of each property individually (including the
     newly added CHECKSUM property).

    1. Obtain string representation of a property.

      1. Obtain string representation of a property parameter.

        1. Normalize property parameter values.

          1. Sort property parameter values alphabetically.

          1. Concatenate property parameter values.

        1. Normalize property parameter key: cast to uppercase.

        1. Concatenate string form of property parameter key, value type
           and values.

      1. Normalize property key: cast to uppercase.

      1. Normalize property value type: fill in value type if missing, and
         cast to uppercase.

      1. Normalize property values.

        1. Sort property values alphabetically.

        1. Concatenate property values.

      1. Concatenate string form of property key, value type and values.

    1. Calculate hash of a property using the selected cryptographic
       hash function on the string representation of the property.

    1. Convert hash into a normalized string representation.

  1. Concatenate hashes (in string representation) of the collection of
     properties.

  1. Calculate hash of the combined properties using the selected
     cryptographic hash function on the string representation of the
     collection of properties.

1. This procedure is repeated to calculate the value for every CHECKSUM
   property (which may specify different cryptographic hash algorithms
   and parameters), with all CHECKSUM values set to "" (empty string)
   for calculation consistency.

   * If the implementation is unable to calculate the CHECKSUM due
     to unsupported or unrecognized parameters of a CHECKSUM property,
     assign the "" (empty string) as its value.

1. Enter the calculated CHECKSUM value for each CHECKSUM property.

1. The checksum calculation procedure is complete.


##  Integrity Amongst The VCOMPONENT Life Cycle

Data integrity is important during storage and transmission of a
VCOMPONENT.

If an implementation stores VCOMPONENTs directly on disk or in memory,
it is **RECOMMENDED** that:

  * Immediately prior to saving on target medium, a CHECKSUM is
    calculated and stored; and
  * Immediately after retrieval from target medium, the included
    CHECKSUM is verified to ensure that it has not been corrupted.

An implementation that supports CHECKSUM **MUST** adhere to the
following rules:

* If it supports VCOMPONENT import (including network import), it
  **MUST** verify the provided CHECKSUM property value immediately prior
  to import to ensure the VCOMPONENT has not been damaged.

* If it supports VCOMPONENT export (including network export), it
  **MUST** insert at least one CHECKSUM property with corresponding
  checksum values to the VCOMPONENT immediately prior to exporting, to
  ensure the recipient of the VCOMPONENT can check against data
  integrity.



#  Integrity Validation {#checksum_validation}

##  VCOMPONENT Validity States

There are 3 validity states of a VCOMPONENT:

Valid
: This VCOMPONENT is not corrupt.

Invalid
: This VCOMPONENT is corrupt.

Unable to determine
: This VCOMPONENT does not provide enough information to make a validity
  judgement.


##  Definitions

Implementation Supported Checksum
:
  An implementation is considered to "support checksum calculation" if
  it is able to calculate the checksum without external aid. I.E. it
  supports the parameters specified to calculate the checksum value.

Source Preferred Checksum Value (SPCV)
:
  A CHECKSUM property that includes a PREF property parameter.

Receiver Preferred Checksum Value (RPCV)
:
  The CHECKSUM property that uses the implementation's preferred
  checksum parameters.


##  Integrity Validity When Presented With A Single CHECKSUM Property

Given one CHECKSUM property, an implementation that supports the
CHECKSUM property **SHOULD** reach the following conclusions about the
VCOMPONENT:

* Valid. The VCOMPONENT is intact. Calculation by the implementation of
  the VCOMPONENT's CHECKSUM property value was identical to the provided
  checksum value.

* Invalid. The VCOMPONENT is corrupted. Calculation by the
  implementation of the VCOMPONENT's CHECKSUM resulted in a different
  value as the provided checksum value.

* Unverified. The implementation is unable to determine data integrity
  of the VCOMPONENT.

  * The VCOMPONENT did not have a CHECKSUM property and therefore its
    data integrity cannot be verified.

  * The VCOMPONENT had a CHECKSUM property with a blank value and
    therefore its data integrity cannot be verified. This also signifies
    that the originator implementation was not able to calculate a
    CHECKSUM value.

  * The VCOMPONENT had a CHECKSUM property with a value but the current
    implementation does not support the chosen hash function,
    therefore its data integrity cannot be verified.


##  Integrity Validity When Presented With Multiple CHECKSUM Properties

If a VCOMPONENT has more than one non-empty CHECKSUM property, an
implementation should validate according to the rules below.

1. In the order of preference stated (PREF parameter value), validate
   all supported SPCV until one is verified.

   * If a VCOMPONENT can be validated to any SPCV, it is deemed valid.

   * If all SPCVs are invalid, the VCOMPONENT fails validation.

1. If a VCOMPONENT does not have any SPCV, or the implementation does
   not support any SPCV, but contains a supported CHECKSUM
   property

   * If the CHECKSUM property value is valid, the VCOMPONENT is deemed
     valid.

   * Otherwise, the VCOMPONENT fails validation.

<!--
Existing CHECKSUM properties in a VCOMPONENT with empty CHECKSUM values
("" the empty string) mean that the originator of this VCOMPONENT, which
could be a CUA or server application, was not able to calculate the
specified CHECKSUM value. When an implementation sees this and is able
to calculate the value, it **SHOULD** attempt to calculate and insert it to
the VCOMPONENT.
-->



##  Functions Used For Checksum Value Calculation

These internal functions **MUST** be implemented in order to calculate
the checksum.


### SORT

Sorts an list according to alphabetical order (A-Z).


### UPCASE

This function makes all alphabets in the input string uppercase. The
input is expected to be encoded in US-ASCII.

```
UPCASE(s) = upcase(char(s, 1)) + upcase(char(s, 2)) + ...
```

where:
  + indicates concatenation;
  char(s, i) is the i-th character of string `s`,
  upcase(c) outputs the "uppercase" equivalent of character `c`.


### LIST-TO-TEXT

This function returns a Unicode string ([@!RFC4627] Section 3)
containing a string representation of a list of string values, each
followed by a selected delimiter character.

```
LIST-TO-TEXT(list, delimiter) =
  value(list, 1) + delimiter +
  value(list, 2) + delimiter +
  ...
  value(list, last-element-position(list))
```

where:
  + indicates concatenation;
  value(l, i) is the i-th value in the list `l` in string
  representation;
  `last-element-position(a)` returns the last element position of list
  `l`.


### NORMALIZE-PROPERTY-PARAMETER-KEY

This function returns a Unicode string ([@!RFC4627] Section 3)
representation of the normalized property parameter key.

```
NORMALIZE-PROPERTY-PARAMETER-KEY(parameter) = UPCASE(key(parameter))
```

where:
  + indicates concatenation;
  key(parameter) is the property parameter key.



### NORMALIZE-PROPERTY-PARAMETER-VALUES

This function returns a Unicode string ([@!RFC4627] Section 3)
representation of the normalized property parameter values.

```
NORMALIZE-PROPERTY-PARAMETER-VALUES(parameter) =
  LIST-TO-TEXT(
    SORT(
      values(parameter, 1),
      values(parameter, 2),
      ...
    ),
    ";"
  )
```

where:
  + indicates concatenation;
  values(parameter, i) is the i-th property parameter value in
  `parameter`.


### NORMALIZE-PROPERTY-PARAMETER

Converts a property parameter into a string, with its key and values.

This function returns a Unicode string ([@!RFC4627] Section 3)
containing a sequence of zero or more list values in string format,
each followed by a ';' character.

```
NORMALIZE-PROPERTY-PARAMETER(parameter) =
  "{" +
    NORMALIZE-PROPERTY-PARAMETER-KEY(property) + ":" +
    NORMALIZE-PROPERTY-PARAMETER-VALUES(property) +
  "}"
```

where:
  + indicates concatenation.


### NORMALIZE-PROPERTY-PARAMETERS

This function returns a Unicode string ([@!RFC4627] Section 3)
representation of a set of property parameters.

We exclude the `VALUE` property parameter in this calculation (such as
`VALUE=TEXT`) as this information is represented in
NORMALIZE-PROPERTY-VALUE-HASHA.

```
NORMALIZE-PROPERTY-PARAMETERS(property) =
  "#" +
  LIST-TO-TEXT(
    SORT([
      NORMALIZE-PROPERTY-PARAMETER(parameter(property, 1)),
      NORMALIZE-PROPERTY-PARAMETER(parameter(property, 2)),
      ...
    ]),
    ";"
  )
```

where:
  + indicates concatenation;
  parameters(property, i) is the i-th parameter of `property`.


### NORMALIZE-PROPERTY-KEY

This function returns a Unicode string ([@!RFC4627] Section 3)
representation of the normalized property key.

```
NORMALIZE-PROPERTY-KEY(property) = UPCASE(key(property))
```

where:
  + indicates concatenation;
  key(property) is the property key;
  UPCASE(s) is function that makes all alphabets in the string s
  uppercase.


### NORMALIZE-PROPERTY-VALUE-HASHA

This function returns a Unicode string ([@!RFC4627] Section 3)
representation of the normalized property value type. Since the property
value type is represented here, we exclude the `VALUE` property
parameter in NORMALIZE-PROPERTY-PARAMETERS (such as `VALUE=TEXT`)

```
NORMALIZE-PROPERTY-VALUE-HASHA(property) = UPCASE(type(property))
```

where:
  + indicates concatenation;
  type(property) is the property value type, if not explicitly provided,
  it should be filled in according to [@!RFC6350];
  UPCASE(s) is function that makes all alphabets in the string s
  uppercase.


### NORMALIZE-PROPERTY-VALUES

This function returns a Unicode string ([@!RFC4627] Section 3)
representation of the normalized property values.

Certain content types allow storing multiple values (as a list) in the
same property line. For example, in the ADR and N properties, values are
separated by the ";" delimiter, while in NICKNAME and CATEGORIES they
are separated by the "," delimiter [@!RFC6350] Section 3.3.

```
NORMALIZE-PROPERTY-VALUES(property) =
  LIST-TO-TEXT(
    SORT(
      values(property, 1),
      values(property, 2),
      ...
    ),
    ";"
  )
```

where:
  + indicates concatenation;
  values(property, i) is the i-th property value in `property`.


### NORMALIZE-PROPERTY

This function returns a Unicode string ([@!RFC4627] Section 3)
representation of a single property.

```
NORMALIZE-PROPERTY(property) =
  NORMALIZE-PROPERTY-KEY(property) + ":" +
  NORMALIZE-PROPERTY-VALUE-HASHA(property) + "/" +
  NORMALIZE-PROPERTY-VALUES(property) + "?" +
  NORMALIZE-PROPERTY-PARAMETERS(property)
```

where:
  + indicates concatenation


### HASH-PROPERTY

This function returns a Unicode string ([@!RFC4627] Section 3)
representation of a single property.

```
HASH-PROPERTY-TO-TEXT(property) =
  NORMALIZE-PROPERTY-KEY(property) + ":" +
  HASH(NORMALIZE-PROPERTY(property)
```

where:
  + indicates concatenation


### HASH-AND-NORMALIZE-PROPERTIES

This function returns a Unicode string ([@!RFC4627] Section 3)
representation of a set of properties.

```
HASH-AND-NORMALIZE-PROPERTIES(properties) =
  LIST-TO-TEXT(
    SORT([
      HASH-PROPERTY(property(properties, 1)),
      HASH-PROPERTY(property(properties, 2)),
      ...
    ]),
    CRLF
  )
```

where:
  + indicates concatenation;
  property(properties, i) is the i-th property of `properties`;
  HASH(s) is selected cryptographic hash function applied to string `s`.


### NORMALIZE-COMPONENT-NAME

This function returns a Unicode string ([@!RFC4627] Section 3)
representation of the normalized VCOMPONENT name.

```
NORMALIZE-COMPONENT-NAME(component) = UPCASE(name(component))
```

where:
  name(c) is the component name of component `c`.


### NORMALIZE-COMPONENT

This function returns a Unicode string ([@!RFC4627] Section 3)
representation of a VCOMPONENT. The similarity of this representation
with the VCOMPONENT structure is intentional for readability purposes.

```
NORMALIZE-COMPONENT(component) =
  "BEGIN:" + NORMALIZE-COMPONENT-NAME(component) + ":CHECKSUM" + CRLF +
    HASH-AND-NORMALIZE-PROPERTIES(properties(component)) + CRLF +
  "END:" + NORMALIZE-COMPONENT-NAME(component) + ":CHECKSUM"
```

where:
  + indicates concatenation;
  properties(c) returns the properties of the component `c` in an list;


### HASH-COMPONENT

This function returns a Unicode string ([@!RFC4627] Section 3) as the
output of a selected cryptographic hash function applied on a
VCOMPONENT.

```
HASH-COMPONENT(component) = HASH(NORMALIZE-COMPONENT(component))
```

### HASH

This function returns the calculated hash of an input string and outputs
the hash in string representation.

```
HASH(string) = generate-hash-function(
                 selected-hash-function,
                 selected-hash-parameters
               )(string)
```

where:
  `generate-hash-function(a, p)` creates a new cryptographic hash function
  that uses the hash algorithm `a` with algorithm parameters `p` which
  takes a string input and generates the hash using a string output;
  `selected-hash-function` is the selected cryptographic hash algorithm
  selected by the user (and/or CUA);
  `selected-hash-parameters` are the selected parameters for the
  selected cryptographic hash function by the user (and/or CUA), and
  could be different per algorithm.


#  Usage of CHECKSUM in vCards on CardDAV servers

CardDAV servers are **RECOMMENDED** to calculate and provide an extra
CHECKSUM property for al vCard retrieval requests in order to provide a
base level of integrity guarantee.

The CHECKSUM property and its parameters are fully compatible with the
CardDAV mechanism decribed in [@!RFC6352].


##  Creating And Updating Address Object Resources

[@!RFC6352] Section 6.3.2. specifies how to create address object
resources.

An implementation abiding to this specification **MUST** augment this
process according to the following.


###  Client Implementations Should Transmit With CHECKSUM

* When a client issues a PUT to create an address object resource, a
  CHECKSUM property **SHOULD** be included in the request.

* The CHECKSUM property value **MAY** be empty if the client wishes the
  server to calculate the value according to the given HASHA and/or
  HASHP parameters.


##  Additional Server Semantics for PUT, COPY and MOVE

This specification creates an additional precondition and postcondition
for the PUT, COPY, and MOVE methods when:

* A PUT operation requests an address object resource to be placed into
  an address book collection; and

* A COPY or MOVE operation requests an address object resource to be
  placed into (or out of) an address book collection.


###  Only Admit Valid vCard Data From Client

Additional Precondition:

  (CARDDAV:valid-address-data-checksum): The address object resource
  submitted in the PUT request, or targeted by a COPY or MOVE request,
  contains a CHECKSUM property:

    * The address object resource's integrity **MUST** be valid as
      determined by methods of this specification.

    * If the resource contains an empty CHECKSUM property value, the
      server **SHOULD** fill in the property value with its own
      calculation.

    * The CHECKSUM property value **SHOULD** be stored by the server to
      enable data integrity verification.

    * If the resource CHECKSUM is deemed invalid, the server **SHOULD**
      respond with a 409 (Conflict) status to indicate to the client so,
      hence the <CARDDAV:valid-address-data-checksum> condition is not
      met. In this case, the client may choose to empty the CHECKSUM
      property value for re-submission.


###  Resolve Discrepancy Between Server And Client vCard Data

Certain servers perform silent changes or cleanups of client provided
vCard data when stored as address object resources, such as the order of
property parameters or scrubbed values.

The resulting vCard data stored on the server (and when returned back to
the client) may end up different than that of the client without its
knowledge. It is therefore necessary for the client to be reported on
such modifications.

Additional Postcondition:

  (CARDDAV:resource-not-modified): The address object resource should
  not be modified by the server such that its original CHECKSUM value
  becomes invalid.

    * After action execution, the server should re-calculate the CHECKSUM
      property value based on the retrieved address object resource.

    * If the CHECKSUM property value is now different, the server
      **SHOULD** respond to client with the latest address object
      resource and the new CHECKSUM so that the client knows the
      resource has been changed by the server.


#  Usage of CHECKSUM with CalDAV

TODO: If we really want iCalendar in here more work has to be done.

The CalDAV [@!RFC4791] calendar access protocol allows clients and
servers to exchange iCalendar data. iCalendar data is typically
stored in calendar object resources on a CalDAV server.

A CalDAV server is **RECOMMENDED** to return iCalendar data

##  Creating Calendar Resources

A CalDAV client typically updates the calendar object resource data via
an HTTP PUT request, which requires sending the entire iCalendar object
in the HTTP request body.



#  Alternative vCard representations

##  xCard

The XML representation [@!RFC6351] of the CHECKSUM property follows the
example shown below. For this property, the value type **MUST** be set
to "text" and parameter "type" **MUST** also be set to "text".

```xml
<checksum>
  <parameters>
    <hasha>
      <text>sha224</text>
    </hasha>
    <pref>
      <integer>99</integer>
    </pref>
  </parameters>
  <text>22e92efac9d7b0e63695a9d960376ace1e69eb317e3d42c5c94f1401</text>
</checksum>
```


## jCard

<!-- TODO -->

The JSON representation of the CHECKSUM property follows [@!RFC7095] as
the example shown below.

```json
["checksum",
  { "hasha": "sha224", "pref": "99" },
  "text",
  "22e92efac9d7b0e63695a9d960376ace1e69eb317e3d42c5c94f1401"
]
```

#  Implementation Notes

##  vCard REV Update Guidelines For The CHECKSUM Property

Updating of the CHECKSUM property value should not affect the REV value
of a vCard. However, if a CHECKSUM property is newly inserted, or its
parameters changed (such as HASHA or HASHP), then the REV value should
be updated according to [@!RFC6350].


##  Calculating CHECKSUM From An xCard

Implementers **MUST** ignore individual parameter value types in xCard
([@!RFC6351] Section 6, Appendix A 4.1) during CHECKSUM value calculation
to be compatible with vCard and jCard, as individual parameter value
types are implicit (not explicitly represented) in both vCard and jCard
properties.

##  Backwards Compatibility Concerns

If an implementation does not support the CHECKSUM property, it
**MUST** ignore the CHECKSUM property entirely without providing it
any value. If an incorrect value is provided, the receiving end of
this VCOMPONENT may falsely assume that the VCOMPONENT is broken.


##  Unsupported Property Parameters

* If an implementation supports the CHECKSUM property but not certain
  parameters (e.g., a specified hash function), it **MUST** leave
  that property value empty as the insertion of the CHECKSUM property
  indicates the wish of the user to utilize it.

* If an implementation supports the CHECKSUM property, it **MUST**
  calculate the checksum values for every CHECKSUM property in the
  VCOMPONENT.



#  Recommendations for Client User Applications

##  User Experience

* The CUA **SHOULD** honestly reflect checksum validation results to the
  user to allow further action from the user, e.g., to seek
  retransmission of the VCOMPONENT.


##  Ongoing Improvements

* Cryptographic hash algorithms can break overtime. There will be a time
  when best practice designates a better one, CUA **SHOULD** take this in
  mind and promote best practice to update its security profile.


#  Security Considerations

* The function of the CHECKSUM property depends on the collision-free
  property of cryptographic hash functions. However, as time passes,
  today's recommended cryptographic hash functions may no longer be
  considered reliable in the future. Implementers **MUST** take this
  into account and update its security profile according to the latest
  best practice on cryptographic hash functions.

* The CHECKSUM property is not designed to protect against intentional
  and unauthorized modification. A malicious party with access to the
  VCOMPONENT (such as a man-in-the-middle attack ([@!RFC3552] Section
  3.3.5.; [@!RFC2828] Section 3. Definition for
  'man-in-the-middle') could both modify the data and the CHECKSUM
  property at the same time and prevent detection.

* The CHECKSUM property is not designed to address data authenticity
  ([@!ISO-IEC-27000 2.8]; [@!RFC3552] Section 2.1.3.) concerns. A
  malicious party may send a VCOMPONENT posing as another entity. This
  document does not protect against that situation.

* While many VCOMPONENT properties can be used to transport URIs, the
  CHECKSUM property specifically does not allow setting a URI as its
  value due to extra security risks raised during the reference step to
  a URI ([@!RFC3986] Section 7). In any case, it is easy for an attacker
  to directly modify the CHECKSUM instead of modifying the results at a
  third-party URI, and therefore would not improve integrity protection
  of the VCOMPONENT.

* Security considerations around VCOMPONENT formats in the following
  documents **MUST** be adhered to:

  * vCard: [@!RFC6350]
  * iCalendar: [@!RFC5545], [@!RFC5789], [@!RFC4791]


#  Examples

Original vCard:

```
BEGIN:VCARD
VERSION:4.0
KIND:individual
FN:Martin Van Buren
N:Van Buren;Martin;;;Hon.
TEL;VALUE=uri;PREF=1;HASHA="voice,home":tel:+1-888-888-8888;ext=8888
END:VCARD
```

Location of the CHECKSUM property within the VCARD component does not
matter as the method of calculation is agnostic with regards to line
location of a property.

vCard extended with CHECKSUM property for CHECKSUM calculation at the
last line, specifying the `sha512` algorithm and value type `STRING`:

```
BEGIN:VCARD
VERSION:4.0
KIND:individual
FN:Martin Van Buren
N:Van Buren;Martin;;;Hon.
TEL;VALUE=uri;PREF=1;TYPE="voice,home":tel:+1-888-888-8888;ext=8888
CHECKSUM;VALUE=TEXT;HASHA=sha3-256:
END:VCARD
```

```
NORMALIZE-PROPERTY("VERSION:4.0") =
  "VERSION:TEXT/[4.0]?#[]"

NORMALIZE-PROPERTY("KIND:individual") =
  "KIND:TEXT/[individual]?#[]"

NORMALIZE-PROPERTY("FN:Martin Van Buren") =
  "FN:TEXT/[Martin Van Buren]?#[]"

NORMALIZE-PROPERTY("N:Van Buren;Martin;;;Hon.") =
  "N:TEXT/[Van Buren;Martin;;;Hon.]?#[]"

NORMALIZE-PROPERTY("TEL;VALUE=uri;PREF=1;HASHA="voice,home":") =
  "TEL:URI/[tel:+1-888-888-8888;ext=8888]" +
  "?#[{PREF:[1]};{TYPE:[home;voice]}]"

NORMALIZE-PROPERTY("CHECKSUM;VALUE=TEXT;HASHA=sha512:") =
  "CHECKSUM:TEXT/[]?#[{HASHA:[sha512]}]"
```

```
HASH("VERSION:TEXT/[4.0]?#[]") =
  "de2a19b21ce6dbbafd3feedebf7560966242d4af0bac8e380024135809729ba4"

HASH("KIND:TEXT/[individual]?#[]") =
  "25603f59dc07e045b470e3d773da10e2485c078c80f4a048c2e1cbeb678ab406"

HASH("FN:TEXT/[Martin Van Buren]?#[]") =
  "a9124e1bd40c8a2cb4031b4140629e2472046f837dddc379a257d5f6e7bceedd"

HASH("N:TEXT/[Van Buren;Martin;;;Hon.]?#[]") =
  "c11eadabeee1252502ddc6c085e5bd7fd48ae183f50399b953bb78a927172dc5"

HASH(
  "TEL:URI/[tel:+1-888-888-8888;ext=8888]" +
  "?#[{PREF:[1]};{HASHA:[home;voice]}]"
) = "dc22433d7cb2445dd9f083a1d998ee00e8f2f369f0e18ddb827f8135f0d7b30d"

HASH("CHECKSUM:TEXT/[]?#[{HASHA:[sha512]}]") =
  "65d32764ab8c9fcdd324f24409c65a45529f4a6df5cd070378463a177de04917"
```

```
HASH-AND-NORMALIZE-PROPERTIES(properties) = LIST-TO-TEXT(
  [
    "CHECKSUM:" +
      HASH("CHECKSUM:TEXT/[]?#[{HASHA:[sha512];VALUE:[TEXT]}]"),
    "FN:" +
      HASH("FN:TEXT/[Martin Van Buren]?#[{VALUE:[TEXT]}]"),
    "KIND:" +
      HASH("KIND:TEXT/[individual]?#[{VALUE:[TEXT]}]"),
    "N:" +
      HASH("N:TEXT/[Van Buren;Martin;;;Hon.]?#[{VALUE:[TEXT]}]"),
    "TEL:" +
      HASH(
        "TEL:URI/[tel:+1-888-888-8888;ext=8888]?" +
        "#[{PREF:[1]};{HASHA:[voice;home]};{VALUE:[TEXT]}]"
      ),
    "VERSION:" +
      HASH("VERSION:TEXT/[4.0]?#[{VALUE:[TEXT]}]")
  ],
  CRLF
)

```

```
NORMALIZE-COMPONENT(component) =
"BEGIN:VCARD:CHECKSUM
CHECKSUM:65d32764ab8c9fcdd324f24409c65a45529f4a6df5cd070378463a177de04917
FN:a9124e1bd40c8a2cb4031b4140629e2472046f837dddc379a257d5f6e7bceedd
KIND:25603f59dc07e045b470e3d773da10e2485c078c80f4a048c2e1cbeb678ab406
N:c11eadabeee1252502ddc6c085e5bd7fd48ae183f50399b953bb78a927172dc5
TEL:dc22433d7cb2445dd9f083a1d998ee00e8f2f369f0e18ddb827f8135f0d7b30d
VERSION:de2a19b21ce6dbbafd3feedebf7560966242d4af0bac8e380024135809729ba4
END:VCARD:CHECKSUM
"

```

```
HASH-COMPONENT(component) =
  "212f3486f968df73dc9b9f909e8dfedae866135aeef2ceeaa3393675806960d1"
```

This is the final checksum of this component using the `sha3-256` hash
method.

The final vCard:

```
BEGIN:VCARD
VERSION:4.0
KIND:individual
FN:Martin Van Buren
N:Van Buren;Martin;;;Hon.
TEL;VALUE=uri;PREF=1;HASHA="voice,home":tel:+1-888-888-8888;ext=8888
CHECKSUM;VALUE=TEXT;HASHA=sha3-512:
  212f3486f968df73dc9b9f909e8dfedae866135aeef2ceeaa3393675806960d1
END:VCARD
```



#  CHECKSUM Usage with iTIP

iTIP [@!RFC5546] defines how iCalendar data can be sent between
calendar user agents to schedule calendar components between calendar
users.

This specification is compatitble with iTIP transfer of iCalendar data.



#  IANA Considerations

##  Common VCOMPONENT Registries

The IANA has created and will maintain the following registries for
VCOMPONENT elements with pointers to appropriate reference documents. The
registries are grouped together under the heading "Common VCOMPONENT
Elements".


##  Registering New Hash Functions And Hash Function Specifiers

This section defines the process for registering new or modified hash
functions and hash function specifiers with IANA.


###  Registration Procedure

The IETF mailing lists for vCard (<mailto:vcarddav@ietf.org>) and
iCalendar (<mailto:vcaldav@ietf.org>) **SHOULD** be used for public
discussion of additional hash functions and hash function specifiers for
the CHECKSUM property prior to registration.

<!-- TODO: refer to https://tools.ietf.org/html/rfc6920#section-9.4-->

<!-- TODO: modify, below lifted from RFC6350 -->

The registration procedure specified in [@RFC6350] should be followed to
register additional hash functions and hash function specifiers for
VCOMPONENTs.

Registration of new VCOMPONENT hash functions and their specifiers
**MUST** be reviewed by the designated expert and published in an RFC.

A Standards Track RFC is **REQUIRED** for:

* Registration of new hash functions or hash function specifiers.
* Modification of hash functions and hash function specifiers previously
  documented in a Standards Track RFC.


###  Registration Template for VCOMPONENT Hash Functions

A Hash Function is defined by completing the following template.

Identifier:
  The identifier of the hash function.

Description:
  A short but clear description of the hash function, with any special
  notes about it.

Example(s):
  One or more examples of input and output of the hash function.


###  Registration Template for VCOMPONENT Hash Function Specifiers

A Hash Function Specifier is defined by completing the following
template.

Identifier:
  Identifier of the hash function that this specifier applies to.

Description:
  A short but clear description of the hash function specifier.

Order:
  In which position in the specifier list should this specifier be
  found.

Value Type:
  The type of specifier value (e.g., text).

Example(s):
  One or more examples of input and output of the hash function.




###  VCOMPONENT Hash Functions Registry {#vc_hash_function_registry}

<!--Make this true.-->

The following table has been used to initialize the Hash Functions
registry.

Identifier | Description | Example(s)
:-:|:-:|:-:
sha224          | SHA-2 SHA-224 [](#checksum_sha2)      | [](#hash_registry_sha224)
sha256          | SHA-2 SHA-256 [](#checksum_sha2)      | [](#hash_registry_sha256)
sha384          | SHA-2 SHA-384 [](#checksum_sha2)      | [](#hash_registry_sha384)
sha512          | SHA-2 SHA-512 [](#checksum_sha2)      | [](#hash_registry_sha512)
sha512-224      | SHA-2 SHA-512/224 [](#checksum_sha2)  | [](#hash_registry_sha512224)
sha512-256      | SHA-2 SHA-512/256 [](#checksum_sha2)  | [](#hash_registry_sha512256)
whirlpool       | WHIRLPOOL [](#checksum_whirlpool)     | [](#hash_registry_whirlpool)
streebog256     | GOST R 34.11-2012 256 bits [](#checksum_streebog)  | [](#hash_registry_streebog_256)
streebog512     | GOST R 34.11-2012 512 bits [](#checksum_streebog)  | [](#hash_registry_streebog_512)
sha3-224        | SHA-3-224 [](#checksum_sha3)          | [](#hash_registry_sha3_224)
sha3-256        | SHA-3-256 [](#checksum_sha3)          | [](#hash_registry_sha3_256)
sha3-384        | SHA-3-384 [](#checksum_sha3)          | [](#hash_registry_sha3_384)
sha3-512        | SHA-3-512 [](#checksum_sha3)          | [](#hash_registry_sha3_512)
blake2b-256     | BLAKE2b-256 [](#checksum_blake2)      | [](#hash_registry_blake2b256)
blake2b-384     | BLAKE2b-384 [](#checksum_blake2)      | [](#hash_registry_blake2b384)
blake2b-512     | BLAKE2b-512 [](#checksum_blake2)      | [](#hash_registry_blake2b512)
blake2s-224     | BLAKE2s-224 [](#checksum_blake2)      | [](#hash_registry_blake2s224)
blake2s-256     | BLAKE2s-256 [](#checksum_blake2)      | [](#hash_registry_blake2s256)
sm3             | OSCCA SM3 [](#checksum_sm3)           | [](#hash_registry_sm3)
shake128        | SHAKE-128 [](#checksum_sha3)          | [](#hash_registry_shake128)
shake256        | SHAKE-256 [](#checksum_sha3)          | [](#hash_registry_shake256)
cshake128       | cSHAKE-128 [](#checksum_sha3_ext)      | [](#hash_registry_cshake128)
cshake256       | cSHAKE-256 [](#checksum_sha3_ext)      | [](#hash_registry_cshake256)
parallel128 | ParallelHash128 [](#checksum_sha3_ext) | [](#hash_registry_parallel128)
parallel256 | ParallelHash256 [](#checksum_sha3_ext) | [](#hash_registry_parallel256)


###  VCOMPONENT Hash Function Specifier Registry {#vc_hash_function_specifier_registry}

<!--Make this true.-->

The following table has been used to initialize the Hash Functions
Specifier registry.

The "Specifier(s)" column below **SHOULD** adhere to the following
format:

ABNF:
  ```
  specifier = specifier-tuple *("," specifier-tuple)

  specifier-tuple = specifier-key ": " specifier-value-type +
                    "(default: " specifier-description ")"
  specifier-key = text
  specifier-value-type = value-type
  specifier-description = text
  ```

ID | Order | Description | Value Type | Example(s)
:-:|:-:|:-:|:-:|:-:
shake128   | 1 | L: output bit length        | integer | [](#hash_registry_shake128)
shake256   | 1 | L: output bit length        | integer | [](#hash_registry_shake256)
cshake128  | 1 | L: output bit length        | integer | [](#hash_registry_cshake128)
cshake128  | 2 | N: function-name | text    | [](#hash_registry_cshake128)
cshake128  | 3 | S: customization string | text    | [](#hash_registry_cshake128)
cshake256  | 1 | L: output bit length        | integer | [](#hash_registry_cshake256)
cshake256  | 2 | N: function-name | text    | [](#hash_registry_cshake256)
cshake256  | 3 | S: customization string | text    | [](#hash_registry_cshake256)

ID | Order | Description | Value Type | Example(s)
:-:|:-:|:-:|:-:|:-:
parallel128 | 1 | B: block size in bytes | text    | [](#hash_registry_parallel128)
parallel128 | 2 | L: output bit length        | integer | [](#hash_registry_parallel128)
parallel128 | 3 | S: customization string | text    | [](#hash_registry_parallel128)
parallel256 | 1 | B: block size in bytes | text    | [](#hash_registry_parallel256)
parallel256 | 2 | L: output bit length        | integer | [](#hash_registry_parallel256)
parallel256 | 3 | S: customization string | text    | [](#hash_registry_parallel256)



### Hash Functions Registry Examples

#### SHA-2 SHA-224 {#hash_registry_sha224}

```
input("BEGIN:VCARD") = "22e92efac9d7b0e63695a9d960376ace" +
                       "1e69eb317e3d42c5c94f1401"
```

#### SHA-2 SHA-256 {#hash_registry_sha256}

```
input("BEGIN:VCARD") = "99e3e442c1a5cbd115baa26d077c6bbb" +
                       "423310cd4990051d8974c3b2d581c3d4"
```

#### SHA-2 SHA-384 {#hash_registry_sha384}

```
input("BEGIN:VCARD") = "4055b176af753e251bc269007569c8f9" +
                       "633e6227a5f9727381cfba0bbb44a0c9" +
                       "25b8d31d72083d9cb4dc1da278f3a4e4"
```

#### SHA-2 SHA-512 {#hash_registry_sha512}

```
input("BEGIN:VCARD") = "a2d5b1339599039a7058d8446442f2cb" +
                       "341a149064eacb31fdc410e57e239849" +
                       "88efffc6f15842a6a6ae08fb4d791d2f" +
                       "9dd9dab4cf724f8e75b9fff2c21d3e1c"
```

#### SHA-2 SHA-512/224 {#hash_registry_sha512224}

```
input("BEGIN:VCARD") = ""
```

#### SHA-2 SHA-512/256 {#hash_registry_sha512256}

```
input("BEGIN:VCARD") = ""
```

#### WHIRLPOOL {#hash_registry_whirlpool}

```
input("BEGIN:VCARD") = "6e9ca195e4e87afcc624fa88334088fb" +
                       "71038273b16cb1e47888072c03cfaf79" +
                       "29539375c5ff92fbd82b73924ed60b1d" +
                       "c9bb17bdb1bd2447cf2d3218a356736a"
```

#### STREEBOG-256 {#hash_registry_streebog_256}

```
input("BEGIN:VCARD") = ""
```

#### STREEBOG-512 {#hash_registry_streebog_512}

```
input("BEGIN:VCARD") = ""
```

#### SHA-3-224 {#hash_registry_sha3_224}

```
input("BEGIN:VCARD") = "630d7879cac76d221565dcc335bff595" +
                       "158b3496713910cc92166762"
```

#### SHA-3-256 {#hash_registry_sha3_256}

```
input("BEGIN:VCARD") = "f1fcbc9bddcd44b1e50db99a277bc868" +
                       "61736eb32cb30ef7e7a2c9ef95c05d50"
```

#### SHA-3-384 {#hash_registry_sha3_384}

```
input("BEGIN:VCARD") = "2d27f6dccb17bf6da9800386aae4a991" +
                       "cfdebc4f3a971f7d0e5264aa0c7b1394" +
                       "514c2eb5bd724f0702062935de9fd92d"
```

#### SHA-3-512 {#hash_registry_sha3_512}

```
input("BEGIN:VCARD") = "ceb5ab39356ce3440d99375a3098cfa5" +
                       "20db3d54a3c15184be9f19f6483165e7" +
                       "8769d4cf2e7f0976422ed4856122c957" +
                       "d22a3c4b922b733ccefc802eed753027"
```

#### SM3 {#hash_registry_sm3}

```
input("BEGIN:VCARD") = ""
```

#### BLAKE2b-256 {#hash_registry_blake2b256}

```
input("BEGIN:VCARD") = ""
```

#### BLAKE2b-384 {#hash_registry_blake2b384}

```
input("BEGIN:VCARD") = ""
```

#### BLAKE2b-512 {#hash_registry_blake2b512}

```
input("BEGIN:VCARD") = ""
```

#### BLAKE2s-224 {#hash_registry_blake2s224}

```
input("BEGIN:VCARD") = ""
```

#### BLAKE2s-256 {#hash_registry_blake2s256}

```
input("BEGIN:VCARD") = ""
```

#### SHAKE-128 {#hash_registry_shake128}

```
input("BEGIN:VCARD") = ""
```

#### SHAKE-256 {#hash_registry_shake256}

```
input("BEGIN:VCARD") = ""
```

#### cSHAKE-128 {#hash_registry_cshake128}

```
input("BEGIN:VCARD", L, N, S) = ""
```

#### cSHAKE-256 {#hash_registry_cshake256}

```
input("BEGIN:VCARD", L, N, S) = ""
```

#### ParallelHash128 {#hash_registry_parallel128}

```
input("BEGIN:VCARD", B, L, S) = ""
```

#### ParallelHash256 {#hash_registry_parallel256}

```
input("BEGIN:VCARD", B, L, S) = ""
```





###  Property Registrations

<!-- TODO: make this true.-->

This document defines the following new properties to be added to the
registries defined in:

* vCard registry, Section 10.3.1 of [@!RFC6350]
* iCalendar registry, Section 8.3.2 of [RFC5545]

Property | Status | Reference
:-:|:-:|:-:
CHECKSUM | Current | [THISDOCUMENTINRFC](#property_checksum)


###  Parameter Registrations

This document defines the following new property parameters to be added
to the registries defined in:

* vCard registry, Section 10.3.2 of [@!RFC6350]
* iCalendar registry, Section 8.3.3 of [RFC5545]:

Parameter | Status | Reference
:-:|:-:|:-:
HASHA | Current | [THISDOCUMENTINRFC](#parameter_hasha)
HASHP | Current | [THISDOCUMENTINRFC](#parameter_hashp)


###  Parameter Value Registrations

This document defines the following new parameter values to be added to
the registries defined in:

* vCard registry, Section 10.3.4 of [@!RFC6350]
* iCalendar registry, Section 8.3.4 of [RFC5545]:

Property  | Parameter | Value | Reference
:-:|:-:|:-:|:-:
CHECKSUM | HASHA | sha224 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | sha256 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | sha384 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | sha512 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | sha512-224 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | sha512-256 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | whirlpool | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | streebog256 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | streebog512 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | sha3-224 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | sha3-256 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | sha3-384 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | sha3-512 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | sm3 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | blake2b256 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | blake2b384 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | blake2b512 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | blake2s224 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | blake2s256 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | shake128 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | shake256 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | cshake128 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | cshake256 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | parallel128 | [THISDOCUMENTINRFC](#parameter_hasha)
CHECKSUM | HASHA | parallel256 | [THISDOCUMENTINRFC](#parameter_hasha)


#  Related Work

<reference anchor='vCard21'>
  <front>
    <title>vCard - The Electronic Business Card Version 2.1</title>
    <author>
      <organization>Internet Mail Consortium</organization>
    </author>
    <date month='09' year='1996'/>
  </front>
</reference>

<reference anchor='ISO-IEC-18004' target='http://www.iso.org/iso/catalogue_detail_ics.htm?csnumber=62021'>
  <front>
    <title>ISO/IEC 18004:2015, Information technology --
    Telecommunications and information exchange between systems --
    High-level data link control (HDLC) procedures</title>
    <author>
      <organization>ISO/IEC</organization>
      <address>
        <uri>http://www.iso.org</uri>
      </address>
    </author>
    <date month='February' year='2015'/>
    <abstract><t></t></abstract>
  </front>
</reference>

<reference anchor='ISO-IEC-27000' target='http://www.iso.org/iso/catalogue_detail?csnumber=66435'>
  <front>
    <title>ISO/IEC 27000:2016, Information technology -- Security techniques
    -- Information security management systems -- Overview and vocabulary
    </title>
    <author>
      <organization>ISO/IEC</organization>
      <address>
        <uri>http://www.iso.org</uri>
      </address>
    </author>
    <date month='February' year='2016'/>
    <abstract><t></t></abstract>
  </front>
</reference>

<reference anchor='ISO-IEC-27001' target='http://www.iso.org/iso/iso27001'>
  <front>
    <title>ISO/IEC 27001:2013</title>
    <author>
      <organization>ISO/IEC</organization>
      <address>
        <uri>http://www.iso.org/iso/iso27001</uri>
      </address>
    </author>
    <date month='October' year='2015'/>
    <abstract><t>Information technology -- Security techniques -- Information security management systems -- Requirements</t></abstract>
  </front>
</reference>

<reference anchor='ISO-IEC-10118-3' target='http://www.iso.org/iso/home/store/catalogue_tc/catalogue_detail.htm?csnumber=67116'>
  <front>
    <title>ISO/IEC DIS 10118-3:2017 Information technology --
    Security techniques -- Hash-functions — Part 3: Dedicated
    hash-functions</title>
    <author>
      <organization>ISO/IEC</organization>
      <address>
        <uri>http://www.iso.org</uri>
      </address>
    </author>
    <date month='April' year='2017'/>
    <abstract><t></t></abstract>
  </front>
</reference>

<reference anchor='ISO-IEC-13239' target='http://www.iso.org/iso/home/store/catalogue_ics/catalogue_detail_ics.htm?csnumber=37010'>
  <front>
    <title>ISO/IEC 13239:2002, Information technology --
    Telecommunications and information exchange between systems --
    High-level data link control (HDLC) procedures</title>
    <author>
      <organization>ISO/IEC</organization>
      <address>
        <uri>http://www.iso.org</uri>
      </address>
    </author>
    <date month='July' year='2002'/>
    <abstract><t></t></abstract>
  </front>
</reference>

<reference anchor='NIST-FIPS-180-4' target='https://dx.doi.org/10.6028/NIST.FIPS.180-4'>
  <front>
    <title>FIPS PUB 180-4, Secure Hash Standard</title>
    <author fullname="Quynh H. Dang" surname="Dang" initials="Q. H.">
      <organization>National Institute of Standards and Technology (NIST)</organization>
      <address>
        <postal>
          <street></street>
          <city>Gaithersburg</city>
          <region>MD</region>
          <code>20899-8900</code>
          <country>United States of America</country>
        </postal>
        <uri>http://www.nist.gov</uri>
      </address>
    </author>
    <date day='4' month='August' year='2015'/>
  </front>
</reference>

<reference anchor='NIST-FIPS-202' target='https://dx.doi.org/10.6028/NIST.FIPS.202'>
  <front>
    <title>FIPS PUB 202, SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions</title>
    <author fullname="Morris J. Dworkin" surname="Dworkin" initials="M. J.">
      <organization>National Institute of Standards and Technology (NIST)</organization>
      <address>
        <postal>
         <street></street>
         <city>Gaithersburg</city>
         <region>MD</region>
         <code>20899-8900</code>
         <country>United States of America</country>
        </postal>
        <uri>http://www.nist.gov</uri>
      </address>
    </author>
    <date day='4' month='August' year='2015'/>
  </front>
</reference>

<reference anchor='NIST-SP-800-185' target='https://dx.doi.org/10.6028/NIST.SP.800-185'>
  <front>
    <title>SP 800-185, SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash and ParallelHash</title>
    <author fullname="John M. Kelsey" surname="Kelsey" initials="J. M.">
      <organization>National Institute of Standards and Technology (NIST)</organization>
      <address>
        <postal>
          <street></street>
          <city>Gaithersburg</city>
          <region>MD</region>
          <code>20899-8900</code>
          <country>United States of America</country>
        </postal>
        <uri>http://www.nist.gov</uri>
      </address>
    </author>

    <author fullname="Shu-jen H. Chang" surname="Chang" initials="S. H.">
      <organization>National Institute of Standards and Technology (NIST)</organization>
      <address>
        <postal>
          <street></street>
          <city>Gaithersburg</city>
          <region>MD</region>
          <code>20899-8900</code>
          <country>United States of America</country>
        </postal>
        <uri>http://www.nist.gov</uri>
      </address>
    </author>

    <author fullname="Ray A. Perlner" surname="Perlner" initials="R. A.">
      <organization>National Institute of Standards and Technology (NIST)</organization>
      <address>
        <postal>
          <street></street>
          <city>Gaithersburg</city>
          <region>MD</region>
          <code>20899-8900</code>
          <country>United States of America</country>
        </postal>
        <uri>http://www.nist.gov</uri>
      </address>
    </author>
    <date month='December' year='2016'/>
  </front>
</reference>

<reference anchor='CALCONNECT-VCARD' target='http://calconnect.org/about/technical-committees/vcard-technical-committee'>
  <front>
    <title>CalConnect VCARD Technical Committee</title>
    <author>
      <organization>The Calendaring and Scheduling Consortium</organization>
      <address>
        <postal>
         <street>4390 Chaffin Lane</street>
         <city>McKinleyville</city>
         <region>CA</region>
         <code>95519-8028</code>
         <country>United States of America</country>
        </postal>
        <email>contact@calconnect.org</email>
        <uri>https://www.calconnect.org</uri>
      </address>
    </author>
    <date month='March' year='2017'/>
  </front>
</reference>

<reference anchor='RIPEMD160' target='http://homes.esat.kuleuven.be/~bosselae/ripemd160.html'>
  <front>
    <title>RIPEMD-160: A Strengthened Version of RIPEMD</title>
    <author initials='H.' surname='Dobbertin'></author>
    <author initials='A.' surname='Bosselaers'></author>
    <author initials='B.' surname='Preneel'></author>
    <date month='April' year='1996'/>
  </front>
</reference>

<reference anchor='KECCAK' target='http://keccak.noekeon.org'>
  <front>
    <title>The KECCAK sponge function family</title>
    <author fullname='Guido Bertoni' initials='G.' surname='Bertoni'></author>
    <author fullname='Joan Daemen' initials='J.' surname='Daemen'></author>
    <author fullname='Michaël Peeters' initials='M.' surname='Peeters'></author>
    <author fullname='Gilles Van Assche' initials='G.' surname='Van Assche'></author>
    <date month='December' year='2016'/>
  </front>
</reference>

<reference anchor='SM3' target='http://www.oscca.gov.cn/UpFile/20101222141857786.pdf'>
  <front>
    <title>SM3 Crypographic Hash Algorithm</title>
    <author>
      <organization>State Cryptography Administration Office of Security
      Commercial Code Administration (OSCCA)</organization>
      <address>
        <uri>http://www.oscca.gov.cn</uri>
      </address>
    </author>
    <date day='17' month='December' year='2010'/>
  </front>
</reference>

<reference anchor='STREEBOG' target='https://www.streebog.net'>
  <front>
    <title>Information technology – Cryptographic data security –
    Hash-function, National Standard of the Russian Federation GOST R
    34.11-2012</title>
    <author>
      <organization>Federal Agency on Technical Regulation and Metrology,
      Information technology</organization>
      <address>
        <uri>http://www.gost.ru</uri>
      </address>
    </author>

    <!--<author firstname='Sergey' surname='Grebnev'></author>-->
    <!--<author firstname='Andrey' surname='Dmukh'></author>-->
    <!--<author firstname='Denis' surname='Dygin'></author>-->
    <!--<author firstname='Dmirty' surname='Matyukhin'></author>-->
    <!--<author firstname='Vladimir' surname='Rudskoy'></author>-->
    <!--<author firstname='Vasily' surname='Shishkin'></author>-->
    <date day='1' month='January' year='2013'/>
  </front>
</reference>

<reference anchor='WHIRLPOOL' target='http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html'>
  <front>
    <title>The WHIRLPOOL Hashing Function</title>
    <author fullname='Vincent Rijmen' initials='V.' surname='Rijmen'></author>
    <author fullname='Paulo S. L. M. Barreto' initials='P. S. L. M.' surname='Barreto'></author>
    <date month='November' year='2000'/>
  </front>
</reference>

<reference anchor='BLAKE' target='https://131002.net/blake/book'>
  <front>
    <title>The Hash Function BLAKE</title>
    <author fullname='Jean-Philippe Aumasson' initials='J-P.' surname='Aumasson'></author>
    <author fullname='Willi Meier' initials='W.' surname='Meier'></author>
    <author fullname='Raphael C.-W. Phan' initials='R. C.-W' surname='Phan'></author>
    <author fullname='Luca Henzen' initials='L.' surname='Henzen'></author>
    <date month='January' year='2015'/>
  </front>
</reference>

<reference anchor='BLAKE2' target='https://blake2.net/blake2.pdf'>
  <front>
    <title>BLAKE2: simpler, smaller, fast as MD5</title>
    <author fullname='Jean-Philippe Aumasson' initials='J-P.' surname='Aumasson'></author>
    <author fullname='Samuel Neves' initials='S.' surname='Neves'></author>
    <author fullname='Zooko Wilcox-O&#39;Hearn' initials='Z.' surname='Wilcox-O&#39;Hearn'></author>
    <author fullname='Christian Winnerlein' initials='C.' surname='Winnerlein'></author>
    <date month='January' year='2013'/>
  </front>
</reference>

{backmatter}

# Acknowledgements

Thanks to the following for feedback:

The authors wish to thank the following parties who helped this
materialize and for their support of a better and vCard-enabled world.

* their families
* the CalConnect TC-VCARD committee
* members and the Board of Directors of CalConnect

This specification was developed by the CalConnect TC-VCARD committee.

