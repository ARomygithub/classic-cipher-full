require 'base64'
class HomeController < ApplicationController
  def index
    result_id = params[:id]
    @result_plain = ""
    @result_base64 = ""
    if result_id
      @result = Result.find_by(id: result_id)
      if @result
        @result_plain = @result.plain
        @result_base64 = @result.base64
      end
    end
    @select_type = params[:select_type]
    unless @select_type
      @select_type = "text"
    end
    @input_text = params[:input_text]
    unless @input_text
      @input_text = ""
    end
    @input_file = params[:input_file]
    unless @input_file
      @input_file = ""
    end
    @cipher_type = params[:cipher_type]
    unless @cipher_type
      @cipher_type = "Vigenere Cipher"
    end
    @string_key = params[:string_key]
    unless @string_key
      @string_key = ""
    end
  end

  def submit
    @select_type = params[:select_type]
    @input_text = params[:input_text]
    @input_file = params[:input_file]
    @cipher_type = params[:cipher_type]
    @string_key = params[:string_key]

    plain = ""
    base64 = ""
    if @cipher_type == "Vigenere Cipher"
      if params[:commit] == "encrypt"
        base64 = vigenere_encrypt(@input_text, @string_key)
      else
        base64 = vigenere_decrypt(@input_text, @string_key)
      end
      plain = Base64.decode64(base64)
    end
    @result = Result.new(plain: plain, base64: base64)
    @result.save
    redirect_to action: "index", id: @result.id, select_type: @select_type, input_text: @input_text, input_file: @input_file, cipher_type: @cipher_type, string_key: @string_key
  end

  private
  def vigenere_encrypt(plain, key)
    plain.upcase!
    key.upcase!
    result = ""
    plain.each_char.with_index do |c, i|
      ord = (c.ord - 'A'.ord + key[i % key.length].ord - 'A'.ord) % 26
      result += (ord + 'A'.ord).chr
    end
    Base64.encode64(result)
  end

  def vigenere_decrypt(cipher, key)
    cipher.upcase!
    key.upcase!
    result = ""
    cipher.each_char.with_index do |c, i|
      ord = (c.ord - 'A'.ord - (key[i % key.length].ord - 'A'.ord) + 26) % 26
      result += (ord + 'A'.ord).chr
    end
    Base64.encode64(result)
  end
end
