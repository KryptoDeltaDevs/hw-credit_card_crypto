# frozen_string_literal: true

require 'openssl'
require 'base64'

# ModernSymmetricCipher module:
# Implements AES-based encryption and decryption using a symmetric key.
#
# generate_new_key: Generates a new AES key encoded in Base64.
# encrypt: Encrypts a document using AES encryption and returns a Base64 ciphertext.
# decrypt: Decrypts a Base64 ciphertext back into its original plaintext.
module ModernSymmetricCipher
  ALGORITHM = 'AES-256-CBC' # Using AES with 256-bit key in CBC mode

  # Generates a new 256-bit AES key and encodes it in Base64
  #
  # @return [String] Base64-encoded AES key
  def self.generate_new_key
    key = OpenSSL::Cipher.new(ALGORITHM).random_key
    Base64.strict_encode64(key) # Encode in Base64 for safe transmission
  end

  # Encrypts a given document using AES encryption and returns a Base64 ciphertext
  #
  # @param document [String] The plaintext to be encrypted
  # @param key [String] The Base64-encoded AES key
  # @return [String] Base64-encoded encrypted string
  def self.encrypt(document, key)
    cipher = OpenSSL::Cipher.new(ALGORITHM)
    cipher.encrypt
    cipher.key = Base64.strict_decode64(key) # Decode Base64 key to binary
    iv = cipher.random_iv # Generate a random IV (Initialization Vector)

    encrypted = cipher.update(document) + cipher.final # Encrypt data
    encrypted_data = iv + encrypted # Prepend IV to the encrypted data

    Base64.strict_encode64(encrypted_data) # Encode result in Base64
  end

  # Decrypts a given Base64-encoded ciphertext using AES decryption
  #
  # @param encrypted_cc [String] The Base64-encoded encrypted string
  # @param key [String] The Base64-encoded AES key
  # @return [String] The original plaintext
  def self.decrypt(encrypted_cc, key)
    decipher = OpenSSL::Cipher.new(ALGORITHM)
    decipher.decrypt
    decipher.key = Base64.strict_decode64(key) # Decode Base64 key to binary

    encrypted_data = Base64.strict_decode64(encrypted_cc) # Decode Base64 ciphertext
    iv = encrypted_data[0..15] # Extract IV (AES block size for CBC mode is 16 bytes)
    encrypted_text = encrypted_data[16..-1] # Extract encrypted content (fix for Ruby 2.5)

    decipher.iv = iv # Set IV for decryption
    decipher.update(encrypted_text) + decipher.final # Decrypt data
  end
end
