# frozen_string_literal: true

# encrypt: Encrypts a plaintext string using double transposition.
# decrypt: Decrypts an encrypted string back to the original plaintext.
module DoubleTranspositionCipher
  # Encrypts a given document using the double transposition cipher.
  #
  # @param document [String] The plaintext to be encrypted.
  # @param key [Integer] The encryption key used for randomization.
  # @return [String] The encrypted ciphertext.
  def self.encrypt(document, key)
    _, _, matrix = prepare_matrix(document)

    shuffled_rows = shuffle_rows(matrix, key)
    transposed_matrix = shuffle_columns(shuffled_rows, key)

    transposed_matrix.flatten.join
  end

  # Decrypts a given ciphertext using the double transposition cipher.
  #
  # @param ciphertext [String] The encrypted text to be decrypted.
  # @param key [Integer] The key used for decryption (same as encryption key).
  # @return [String] The original plaintext.
  def self.decrypt(ciphertext, key)
    _, _, matrix = prepare_matrix(ciphertext)

    restored_cols = reverse_shuffle_columns(matrix, key)
    original_matrix = reverse_shuffle_rows(restored_cols, key)

    original_matrix.flatten.join.rstrip
  end

  # Prepares a matrix representation of the text.
  #
  # @param text [String] The input string.
  # @return [Array] The matrix (2D array) with evenly distributed characters.
  def self.prepare_matrix(text)
    length = text.length
    rows = Math.sqrt(length).floor
    cols = (length.to_f / rows).ceil
    matrix = text.chars.each_slice(cols).to_a

    # Ensure all rows have the same number of columns by padding with spaces
    matrix.last.fill(' ', matrix.last.length...cols) if matrix.last.length < cols
    [rows, cols, matrix]
  end

  # Shuffles the row order using the given key.
  #
  # @param matrix [Array<Array<String>>] The character matrix.
  # @param key [Integer] The key used for randomization.
  # @return [Array<Array<String>>] The row-scrambled matrix.
  def self.shuffle_rows(matrix, key)
    row_order = (0...matrix.size).to_a.shuffle(random: Random.new(key))
    row_order.map { |i| matrix[i] }
  end

  # Shuffles the column order using the given key.
  #
  # @param matrix [Array<Array<String>>] The row-scrambled matrix.
  # @param key [Integer] The key used for randomization.
  # @return [Array<Array<String>>] The column-scrambled matrix.
  def self.shuffle_columns(matrix, key)
    col_order = (0...matrix.first.length).to_a.shuffle(random: Random.new(key))
    matrix.map { |row| col_order.map { |j| row[j] } }
  end

  # Reverses the column shuffle to restore original order.
  #
  # @param matrix [Array<Array<String>>] The scrambled matrix.
  # @param key [Integer] The key used for randomization.
  # @return [Array<Array<String>>] The matrix with columns restored.
  def self.reverse_shuffle_columns(matrix, key)
    col_order = (0...matrix.first.length).to_a.shuffle(random: Random.new(key))
    reverse_col_order = col_order.each_with_index.sort_by(&:first).map(&:last)
    matrix.map { |row| reverse_col_order.map { |j| row[j] } }
  end

  # Reverses the row shuffle to restore original order.
  #
  # @param matrix [Array<Array<String>>] The matrix with restored columns.
  # @param key [Integer] The key used for randomization.
  # @return [Array<Array<String>>] The original matrix before encryption.
  def self.reverse_shuffle_rows(matrix, key)
    row_order = (0...matrix.size).to_a.shuffle(random: Random.new(key))
    reverse_row_order = row_order.each_with_index.sort_by(&:first).map(&:last)
    reverse_row_order.map { |i| matrix[i] }
  end
end
