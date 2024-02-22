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
    cipherAll = Array["Vigenere Cipher", "Auto-Key Vigenere Cipher", "Extended Vigenere Cipher", "Playfair Cipher", "Affine Cipher", "Hill Cipher", "Super Enkripsi"]
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
    elsif  @cipher_type == cipherAll[1]
      if params[:commit] == "encrypt"
        base64 = auto_vigenere_encrypt(@input_text, @string_key)
      else
        base64 = auto_vigenere_decrypt(@input_text, @string_key)
      end
      plain = Base64.decode64(base64)
    elsif @cipher_type == cipherAll[3]
      if params[:commit] == "encrypt"
        base64 = playfair_encrypt(@input_text, @string_key)
      else
        base64 = playfair_decrypt(@input_text, @string_key)
      end
      plain = Base64.decode64(base64)
    end
    @result = Result.new(plain: plain, base64: base64)
    @result.save
    redirect_to action: "index", id: @result.id, select_type: @select_type, input_text: @input_text, input_file: @input_file, cipher_type: @cipher_type, string_key: @string_key
  end

  private
  def remove_all_whitespace(str)
    str.gsub(/\s+/, "")
  end

  def vigenere_encrypt(plain, key)
    plain.upcase!
    plain = remove_all_whitespace(plain)
    key.upcase!
    key = remove_all_whitespace(key)
    result = ""
    plain.each_char.with_index do |c, i|
      ord = (c.ord - 'A'.ord + key[i % key.length].ord - 'A'.ord) % 26
      result += (ord + 'A'.ord).chr
    end
    Base64.encode64(result)
  end

  def vigenere_decrypt(cipher, key)
    cipher.upcase!
    cipher = remove_all_whitespace(cipher)
    key.upcase!
    key = remove_all_whitespace(key)
    result = ""
    cipher.each_char.with_index do |c, i|
      ord = (c.ord - 'A'.ord - (key[i % key.length].ord - 'A'.ord) + 26) % 26
      result += (ord + 'A'.ord).chr
    end
    Base64.encode64(result)
  end

  def auto_vigenere_encrypt(plain, key)
    plain.upcase!
    plain = remove_all_whitespace(plain)
    key.upcase!
    key = remove_all_whitespace(key)
    result = ""
    plain.each_char.with_index do |c, i|
      offset = (i < key.length ? key[i].ord : plain[i- key.length].ord) - 'A'.ord
      ord = (c.ord - 'A'.ord + offset) % 26
      result += (ord + 'A'.ord).chr
    end
    Base64.encode64(result)
  end

  def auto_vigenere_decrypt(cipher, key)
    cipher.upcase!
    cipher = remove_all_whitespace(cipher)
    key.upcase!
    key = remove_all_whitespace(key)
    result = ""
    cipher.each_char.with_index do |c, i|
      offset = (i < key.length ? key[i].ord : result[i - key.length].ord) - 'A'.ord
      ord = (c.ord - 'A'.ord - offset + 26) % 26
      result += (ord + 'A'.ord).chr
    end
    Base64.encode64(result)
  end

  def get_key_matrix(key)
    key_mat = Array.new(5) { Array.new(5) }
    key_set = Set.new
    i2 = 0; j2 = 0
    key.each_char do |c|
      if c=='J'
        next
      end
      unless key_set.include?(c)
        key_set.add(c)
        key_mat[i2][j2] = c
        j2 += 1
        if j2 == 5
          j2 = 0
          i2 += 1
        end
      end
    end
    ('A'..'Z').each do |c|
      unless key_set.include?(c) || c == 'J'
        key_mat[i2][j2] = c
        j2 += 1
        if j2 == 5
          j2 = 0
          i2 += 1
        end
      end
    end
    key_mat
  end
  def playfair_encrypt(plain, key)
    plain.upcase!
    plain = remove_all_whitespace(plain)
    key.upcase!
    key = remove_all_whitespace(key)
    result = ""
    key_mat = get_key_matrix(key)
    plain = plain.gsub('J', 'I')
    plain_bigram = []
    i = 0
    while i < plain.length
      if i == plain.length - 1 || plain[i] == plain[i+1]
        plain_bigram.push(plain[i] + 'X')
        i += 1
      else
        plain_bigram.push(plain[i] + plain[i+1])
        i += 2
      end
    end
    plain_bigram.each do |bigram|
      i1 = 0; j1 = 0; i2 = 0; j2 = 0
      key_mat.each_with_index do |row, ii|
        if row.include?(bigram[0])
          i1 = ii
          j1 = row.index(bigram[0])
        end
        if row.include?(bigram[1])
          i2 = ii
          j2 = row.index(bigram[1])
        end
      end
      if i1 == i2
        result += key_mat[i1][(j1+1)%5] + key_mat[i2][(j2+1)%5]
      elsif j1 == j2
        result += key_mat[(i1+1)%5][j1] + key_mat[(i2+1)%5][j2]
      else
        result += key_mat[i1][j2] + key_mat[i2][j1]
      end
    end
    Base64.encode64(result)
  end

  def playfair_decrypt(cipher, key)
    cipher.upcase!
    cipher = remove_all_whitespace(cipher)
    key.upcase!
    key = remove_all_whitespace(key)
    result = ""
    key_mat = get_key_matrix(key)
    i = 0
    while i < cipher.length
      i1 = 0; j1 = 0; i2 = 0; j2 = 0
      key_mat.each_with_index do |row, ii|
        if row.include?(cipher[i])
          i1 = ii
          j1 = row.index(cipher[i])
        end
        if row.include?(cipher[i+1])
          i2 = ii
          j2 = row.index(cipher[i+1])
        end
      end
      if i1 == i2
        result += key_mat[i1][(j1+4)%5] + key_mat[i2][(j2+4)%5]
      elsif j1 == j2
        result += key_mat[(i1+4)%5][j1] + key_mat[(i2+4)%5][j2]
      else
        result += key_mat[i1][j2] + key_mat[i2][j1]
      end
      i += 2
    end
    result = result.gsub('X', '')
    Base64.encode64(result)
  end
end
