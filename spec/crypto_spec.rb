# frozen_string_literal: true

require_relative '../credit_card'
require_relative '../substitution_cipher'
require 'minitest/autorun'
require_relative '../double_trans_cipher'

describe 'Test card info encryption' do
  before do
    @cc = CreditCard.new('4916603231464963', 'Mar-30-2020',
                         'Soumya Ray', 'Visa')
    @key = 3
  end

  describe 'Using Caesar cipher' do
    it 'should encrypt card information' do
      enc = SubstitutionCipher::Caesar.encrypt(@cc, @key)
      _(enc).wont_equal @cc.to_s
      _(enc).wont_be_nil
    end

    it 'should decrypt text' do
      enc = SubstitutionCipher::Caesar.encrypt(@cc, @key)
      dec = SubstitutionCipher::Caesar.decrypt(enc, @key)
      _(dec).must_equal @cc.to_s
    end
  end

  describe 'Using Permutation cipher' do
    it 'should encrypt card information' do
      enc = SubstitutionCipher::Permutation.encrypt(@cc, @key)
      _(enc).wont_equal @cc.to_s
      _(enc).wont_be_nil
    end

    it 'should decrypt text' do
      enc = SubstitutionCipher::Permutation.encrypt(@cc, @key)
      dec = SubstitutionCipher::Permutation.decrypt(enc, @key)
      _(dec).must_equal @cc.to_s
    end
  end

  # TODO: Add tests for double transposition and modern symmetric key ciphers
  #       Can you DRY out the tests using metaprogramming? (see lecture slide)
  describe 'Using Double Transposition cipher' do
    test_cases = [
      'Simple test case',
      "Credit card:#{@cc}",
      '1234567890',
      "Symbols! @\#$%^&*()"
    ]
    test_cases.each do |str|
      it "should encrypt and decrypt '#{str}' correctly" do
        encrypted = DoubleTranspositionCipher.encrypt(str, @key)
        decrypted = DoubleTranspositionCipher.decrypt(encrypted, @key)

        _(encrypted).wont_equal str
        _(encrypted).wont_be_nil
        _(decrypted).must_equal str
      end
    end
  end
end
