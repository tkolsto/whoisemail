
require 'rubygems'
require 'eventmachine'
require 'socket'
require 'whois'
require 'json'

module WhoisEmailLookupServer
   def post_init
      puts "client connecting"
      send_data "Welcome to WhoisEmailLookupServer\n"
   end

   def receive_data(data)
      c_port, c_ip = Socket.unpack_sockaddr_in(get_peername)
      ip = data.inspect.scan(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/).uniq
      ip.each do |i|
         w = Whois.query(i).parser.inspect.scan(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}/i).uniq
         w.each do |c|
            puts "#{c_ip}:#{c_port} -- lookup #{ip} returned #{c}"
         end

         send_data w.to_json + "\n"
      end

      if data =~ /quit|exit/i
         send_data "goodbye!\n"
         close_connection_after_writing
      end

   end

   def unbind
      puts "client disconnecting"
      close_connection
   end
end

EventMachine::run do
   host = 'localhost'
   port = 8080
   EventMachine::start_server host, port, WhoisEmailLookupServer
   puts "Started WhoisEmailLookupServer on #{host}:#{port} "
end
