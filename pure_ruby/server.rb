require 'socket'
require 'digest/sha1'
require 'base64'

# RFC 6455 standard GUID used to generate Sec-WebSocket-Accept during handshake
WS_MAGIC_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'.freeze

# Start TCP server on localhost:3000
server = TCPServer.new('127.0.0.1', 3000)
clients = []
clients_mutex = Mutex.new # Protect shared clients array across threads

puts 'Websocket Server started on port 3000'

# Performs the HTTP Upgrade handshake according to RFC 6455
def handle_handshake(socket)
  # Read HTTP request headers until an empty line (\r\n\r\n) is encountered
  request = ''
  while (line = socket.gets)
    request << line
    break if line.strip.empty?
  end

  # Extract Sec-WebSocket-Key from request headers
  match = request.match(/Sec-WebSocket-Key:\s*([^\r\n]+)/i)
  return false unless match

  # Calculate Sec-WebSocket-Accept: Base64(SHA1(Key + Magic GUID))
  key = match[1].strip
  accept_val = Base64.strict_encode64(Digest::SHA1.digest(key + WS_MAGIC_GUID))

  # Send 101 Switching Protocols response to upgrade HTTP connection to WebSocket
  response = "HTTP/1.1 101 Switching Protocols\r\n" \
             "Upgrade: websocket\r\n" \
             "Connection: Upgrade\r\n" \
             "Sec-WebSocket-Accept: #{accept_val}\r\n\r\n"
  socket.write(response)
  true
end

# Decodes an incoming WebSocket frame received from a client
def read_frame(socket)
  # Byte 1: FIN bit (0x80) & Opcode (0x0F)
  first_byte = socket.read(1)&.ord
  return nil unless first_byte
  
  opcode = first_byte & 0x0F
  return :close if opcode == 0x08 # Opcode 0x8 represents Close Frame

  # Byte 2: Mask bit (0x80) & Payload length (0x7F)
  second_byte = socket.read(1)&.ord
  return nil unless second_byte
  
  is_masked = (second_byte & 0x80) != 0 # Client-to-server frames MUST be masked
  payload_len = second_byte & 0x7F

  # Extended payload length: 126 => next 2 bytes (unsigned 16-bit), 127 => next 8 bytes (unsigned 64-bit)
  if payload_len == 126
    payload_len = socket.read(2).unpack1('n')
  elsif payload_len == 127
    payload_len = socket.read(8).unpack1('Q>')
  end

  # Masking key is 4 bytes if frame is masked
  mask_key = is_masked ? socket.read(4).bytes : nil
  raw_payload = socket.read(payload_len).bytes
  
  # Unmask payload: transformed_byte = original_byte XOR mask_key[i % 4]
  if is_masked
    decoded = raw_payload.each_with_index.map do |byte, i|
      byte ^ mask_key[i % 4]
    end.pack('C*')
  else 
    decoded = raw_payload.pack('C*')
  end

  decoded.force_encoding('UTF-8')
end

# Encodes a string message into a WebSocket text frame (Opcode 0x1, FIN = 1)
def encode_frame(msg)
  bytes = msg.bytes
  length = bytes.length

  # 0x81 = 10000001 in binary (FIN=1 for final fragment, Opcode=0x1 for text frame)
  header = [0x81]
  
  # Server-to-client frames are not masked, so MSB of second byte is 0
  if length <= 125
    header << length
  elsif length <= 65535
    header << 126
    header.concat([length].pack('n').bytes) # 2-byte big-endian
  else 
    header << 127
    header.concat([length].pack('Q>').bytes) # 8-byte big-endian
  end
  
  # Concatenate header bytes with payload bytes
  (header + bytes).pack('C*')
end

# Main connection acceptance loop
loop do
  # Spawn a new thread for each incoming client connection
  Thread.start(server.accept) do |client|
    if handle_handshake(client)
      clients_mutex.synchronize { clients << client }
      puts "[Connect] Client is connected! (Current clients: #{clients.size})"

      begin
        # Continuously read and process frames from client
        while (message = read_frame(client)) 
          break if message == :close

          puts "[Received] #{message}"

          # Broadcast received message to all connected clients
          frame = encode_frame(message)
          clients_mutex.synchronize do
            clients.each do |c|
              begin
                c.write(frame)
              rescue StandardError
                # Silently ignore write failures for broken connections
              end
            end
          end
        end
      rescue StandardError => e
        puts "[Error] #{e.message}"
      ensure
        # Clean up client on disconnect or error
        clients_mutex.synchronize { clients.delete(client) }
        client.close rescue nil
        puts "[Disconnect] Client is disconnected! (Current clients: #{clients.size})"
      end
    else      
      client.close
    end
  end
end
