require 'base64'
require 'matrix'
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
    @affine_m = params[:affine_m]
    unless @affine_m
      @affine_m = 1
    end
    @affine_b = params[:affine_b]
    unless @affine_b
      @affine_b = 0
    end
    @hill_m = params[:hill_m]
    unless @hill_m
      @hill_m = 1
    end
    @hill_key = params[:hill_key]
    unless @hill_key
      @hill_key = [1]
    end
  end

  def submit
    cipherAll = Array["Vigenere Cipher", "Auto-Key Vigenere Cipher", "Extended Vigenere Cipher", "Playfair Cipher", "Affine Cipher", "Hill Cipher", "Super Enkripsi"]
    @select_type = params[:select_type]
    @input_text = params[:input_text]
    @input_file = params[:input_file]
    @cipher_type = params[:cipher_type]
    @string_key = params[:string_key]
    @affine_m = params[:affine_m]
    @affine_b = params[:affine_b]
    @hill_m = params[:hill_m]
    @hill_key = Array.new
    for i in 0...@hill_m.to_i
      for j in 0...@hill_m.to_i
        @hill_key.push(params["hill_key_#{i}_#{j}"])
      end
    end

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
    elsif @cipher_type == cipherAll[4]
      if params[:commit] == "encrypt"
        base64 = affine_encrypt(@input_text, @affine_m, @affine_b)
      else
        base64 = affine_decrypt(@input_text, @affine_m, @affine_b)
      end
      plain = Base64.decode64(base64)
    elsif @cipher_type == cipherAll[5]
      if params[:commit] == "encrypt"
        base64 = hill_encrypt(@input_text, @hill_m, @hill_key)
      else
        base64 = hill_decrypt(@input_text, @hill_m, @hill_key)
      end
      plain = Base64.decode64(base64)
    end
    @result = Result.new(plain: plain, base64: base64)
    @result.save
    redirect_to action: "index", id: @result.id, select_type: @select_type, input_text: @input_text, input_file: @input_file, cipher_type: @cipher_type, string_key: @string_key, affine_m: @affine_m, affine_b: @affine_b, hill_m: @hill_m, hill_key: @hill_key
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

  def affine_encrypt(plain, m, b)
    plain.upcase!
    plain = remove_all_whitespace(plain)
    m = m.to_i
    b = b.to_i
    result = ""
    plain.each_char do |c|
      ord = (m * (c.ord - 'A'.ord) + b) % 26
      result += (ord + 'A'.ord).chr
    end
    Base64.encode64(result)
  end

  def affine_decrypt(cipher, m, b)
    cipher.upcase!
    cipher = remove_all_whitespace(cipher)
    m = m.to_i
    b = b.to_i
    result = ""
    m_inv = 0
    (0..25).each do |i|
      if (m * i) % 26 == 1
        m_inv = i
        break
      end
    end
    cipher.each_char do |c|
      ord = (m_inv * (c.ord - 'A'.ord - b + 26)) % 26
      result += (ord + 'A'.ord).chr
    end
    Base64.encode64(result)
  end

  def hill_encrypt(plain, m, key)
    plain.upcase!
    plain = remove_all_whitespace(plain)
    m = m.to_i
    result = ""
    key_mat = Matrix.build(m) do |row, col|
      key[row * m + col].to_i
    end
    while plain.length % m != 0
      plain += 'X'
    end
    plain.each_char.with_index do |c, i|
      if i % m == 0
        result += (key_mat * Matrix.column_vector(plain.chars[i...i+m]).map { |x| (x.ord - 'A'.ord) }).to_a.flatten.map { |x| ((x%26) + 'A'.ord).chr }.join
      end
    end
    Base64.encode64(result)
  end

  def hill_decrypt(cipher, m, key)
    cipher.upcase!
    cipher = remove_all_whitespace(cipher)
    m = m.to_i
    result = ""
    key_mat = Matrix.build(m) do |row, col|
      key[row * m + col].to_i
    end
    det = key_mat.det
    key_mat_inv = det * key_mat.inv
    det_inv = 0
    for i in 1..25
      if ((det.round.to_i*i % 26)+26)%26 == 1
        det_inv = i
        break
      end
    end
    key_mat_inv = key_mat_inv.map { |x| ((x.round.to_i*det_inv % 26)+26)%26 }
    cipher.each_char.with_index do |c, i|
      if i%m == 0
        result += (key_mat_inv * Matrix.column_vector(cipher.chars[i...i+m]).map { |x| (x.ord - 'A'.ord) }).to_a.flatten.map { |x| (((x.round.to_i%26)+26)%26 + 'A'.ord).chr }.join
      end
    end
    Base64.encode64(result)
  end
end
