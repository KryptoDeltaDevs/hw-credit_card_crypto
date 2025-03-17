# Credit Card Crypto

This assignment requires you to try your hand out at a very common error checking (data integrity) algorithm, and also introduces you to very elementary cryptographic algorithms.

## Retrieving Files

1. Make sure to setup the git tool as we described in class (see online handout on 'Git Version Control'). Also, make sure to create your own SSH keypair and link your public key to Github. You can then clone any public project from Github onto your local machine without a password.
2. Fork this project on Github (a copy is created in your Github account) using the 'Fork' button.
3. Clone _your copy_ of the forked project onto your local machine:
   `git clone git@github.com:[your_username]/hw_3-credit_card_crypto.git`
4. Set the local Ruby version in `.ruby-version` using `rbenv local [version]`
5. Run `bundle install` to install all gems in `Gemfile`; a `Gemfile.lock` file will be created.

## Working on Assignment

While working on this assignment, frequently save your work and push it back to your Github repo:

    git add .
    git commit -m "Enter meaningful description here"
    git push -u origin main

After the first time you have pushed using `-u origin main`, you can subsequently push it simply by doing:

    git push

## Submission

Submission instructions will be provided separately by your instructor. But before submission, make sure each file you have worked on passes the style guide suggested by Rubocop:

    rubocop <your_ruby_file.rb>

## Requirements

This project is in several parts. Make sure you ONLY do the part that is relevant to this week.

### A. Luhn Algorithm

<!-- markdownlint-disable ol-prefix -->

You will write the algorithm used by financial institutions to check whether a credit card number is valid or not, by checking its last digit (checksum). This is done by using the [Luhn Algorithm](http://en.wikipedia.org/wiki/Luhn_algorithm). You can see this algorithm in action at any [online Luhn algorithm calculator](http://planetcalc.com/2464/).

1. Implement the file called `luhn_validator.rb`

- There is one method you must fill out, called `validate_checksum()`. It must check a credit card number and return (`true`/`false`) whether the last checksum digit is correct.
- This week, try to make your code more readable rather than emphasizing performance

2. Implement the file called `credit_card.rb` (see TODO comments):

- mixin the `LuhnValidator` module
- initialize the instance variables
- create a `#to_json` method that converts the instance variables into a [JSON](http://en.wikipedia.org/wiki/JSON) string format

Make sure it passes the `luhn_spec` test that is provided:

    bundle exec ruby spec/luhn_spec.rb

(run the spec file from the root directory of your solution; `bundle exec` ensures that only the gems in your `Gemfile.lock` are used)

Optionally, bench test the performance of your code by running the bench code:

    ruby bench/luhn_bench.rb

3. Submit: Push your individual work to Github. _You may work with others_ and share ideas. However, _each person should submit their own solution_ (see submission details [here](README.md#submission)).

### B. Substitution and Transposition Ciphers

Work as a team to implement three ciphers that we saw in class: the Caesar Cipher, Permutation Cipher and Double Transposition Cipher. These ciphers represent the state of the art of cryptography from antiquity till World War II.

- Implement the `SubstitutionCipher` module in `substitution_cipher.rb`
  - Create encrypt and decrypt methods of both ciphers
    - all methods take plaintext `document` strings with characters are printable ASCII (ord 32-126)
    - all methods take a positive `key` integer
    - all methods return a string (encrypted or decrypted)
    - Make sure the decrypt method recreates the original document given before encryption!
  - Caesar cipher: there is no need to 'wrap' values -- just add/subtract the key to encrypt/decrypt (its ok if the resulting ordinal values are greater than 127)
  - Permutation cipher:
    - assume you can replace with any characters values from 0-127 (ord)
    - start by creating a lookup table of characters by randomly "shuffling" the numbers `(0..127)` using the key
      - See the `Array.shuffle(random: rng)` method
      - See the `Random.new(seed)` method
- Implement the DoubleTranspositionCipher in `double_trans_cipher.rb` (more hints in source file)
  - Write your own tests for the double transposition cipher in `spec/crypto_spec.rb`: Try writing these tests before coding!
  - Can you DRY out all the tests using metaprogramming as we saw in class? (DRY = Do not Repeat Yourself in code)

While coding, make sure it passes all the tests you are provided:

    ruby spec/crypto_spec.rb

### C. Advanced Crypto and Hashing

This week, we enter the world of modern cryptography. Your team must _use the RbNacl library_ for the ModernSymmetricCipher cipher and SHA256 hashing algorithms. We should not implement modern ciphers ourselves for production purposes.

#### C.1. ModernSymmetricCipher

Implement a modern cryptographic encryption method:

- `ModernSymmetricCipher` in `sk_cipher.rb`
- Write your own tests for ModernSymmetricCipher in `spec/crypto_spec.rb`:
  - make sure your implemented tests _all fail before writing_ any code!
  - make sure they pass _one-by-one_ while writing code
  - Can you DRY out all the tests using metaprogramming?
- Note that you are required to return serialized data as Base64:
  - Use `require 'base64'` to use Ruby's Base64 gem
  - Serialize data using: `Base64.strict_encode64(data)` to get a base 64 string
  - Deserialize using: `Base64.strict_decode64(b64_str)`

#### C.2. Hashing

Your team must implement hashing methods for credit card objects. Recall that all objects in Ruby have a `hash` method by default. However, this method does not use the contents of their objects to produce hashes. Furthermore, this hash method cannot produce a cryptographically strong hash.

- Override the default hash: Override the default `hash` method of CreditCard to hash the serialized data of the card _using a cryptographic hash_. Credit cards with identical information should produce identical hashes.
- BUT FIRST: look at the hashing test specs in `spec/hash_spec.rb`
  - _Implement all the test descriptions_ (you are welcome to add your own as well)
  - make sure your implemented tests _all fail_ before writing _any_ code!
  - make sure they pass _one-by-one_ while writing code :)
- We are coming to the end of this assignment -- time to do some cleanup:
  - Add references in `Gemfile` to all the gems you are using in your code and test files.
  - run `rubocop` on all your code to see if your code style is appropriate
