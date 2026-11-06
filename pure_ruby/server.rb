require 'socket'
require 'digest/sha1'
require 'base64'


WS_MAGIC_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'.freeze

server = TCPServer.new('127.0.0.1', 3000)
clients = []
clients_mutex = Mutex.new

puts 'Websocket Server started on port 3000'

def handle_handshake(socket)
  request = ''
  while (line = socket.gets)
    request << line
    break if line.strip.empty?
  end

  match = request.match(/Sec-WebSocket-Key:\s*([^\r\n]+)/i)
  return false unless match

  key = match[1].strip
  accept_val = Base64.strict_encode64(Digest::SHA1.digest(key + WS_MAGIC_GUID))

  response = "HTTP/1.1 101 Switching Protocols\r\n" \
             "Upgrade: websocket\r\n" \
             "Connection: Upgrade\r\n" \
             "Sec-WebSocket-Accept: #{accept_val}\r\n\r\n"
  socket.write(response)
  true
end

def read_frame(socket)
  first_byte = socket.read(1)&.ord
  return nil unless first_byte
  
  opcode = first_byte & 0x0F
  return :close if opcode == 0x08

  second_byte = socket.read(1)&.ord
  return nil unless second_byte
  
  is_masked = (second_byte & 0x80) != 0 
  payload_len = second_byte & 0x7F

  if payload_len == 126
    payload_len = socket.read(2).unpack1('n')
  elsif payload_len == 127
    payload_len = socket.read(8).unpack1('Q>')
  end

  mask_key = is_masked ? socket.read(4).bytes : nil
  raw_payload = socket.read(payload_len).bytes
  
  if is_masked
    decoded = raw_payload.each_with_index.map do |byte, i|
      byte ^ mask_key[i % 4]
    end.pack('C*')
  else 
    decoded = raw_payload.pack('C*')
  end

  decoded.force_encoding('UTF-8')
end

def encode_frame(msg)
  bytes = msg.bytes
  length = bytes.length

  header = [0x81]
  
  if length <= 125
    header << length
  elsif length <= 65535
    header << 126
    header.concat([length].pack('n').bytes)
  else 
    header << 127
    header.concat([length].pack('Q>').bytes)
  end
  
  (header + bytes).pack('C*')
end

loop do
  Thread.start(server.accept) do |client|
    if handle_handshake(client)
      clients_mutex.synchronize { clients << client }
      puts "[Connect] Client is connected! (Current clients: #{clients.size})"

      begin
        while (message = read_frame(client)) 
          break if message == :close

          puts "[Received] #{message}"

          frame = encode_frame(message)
          clients_mutex.synchronize do
            clients.each do |c|
              begin
                c.write(frame)
              rescue StandardError
                # handle error
              end
            end
          end
        end
      rescue StandardError => e
        puts "[Error] #{e.message}"
      ensure
        clients_mutex.synchronize { clients.delete(client) }
        client.close rescue nil
        puts "[Disconnect] Client is disconnected! (Current clients: #{clients.size})"
      end
    else      
      client.close
    end
  end
end