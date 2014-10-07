#!/usr/bin/ruby

require 'packetfu'

# analyze weblog option (-r FILENAME)
optionr = ARGV[0]
weblog = ARGV[1]

# print the incident alert
def print_inc(inc_num, alert_type, pkt)
	print "#{inc_num}. ALERT: #{alert_type} from #{pkt.ip_saddr} (#{pkt.proto.last}) (#{pkt.payload})!\n"
end

# check for a plain-text credit card number
def credit_card?(pkt)
	if pkt.payload.match(/4\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/) != nil
		return true
	elsif pkt.payload.match(/5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/) != nil
		return true
	elsif pkt.payload.match(/6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/) != nil
		return true
	elsif pkt.payload.match(/3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/) != nil
		return true
	else
		return false
	end
end

def live_stream()
cap = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
inc_num = 0
cap.stream.each do |p|
	pkt = PacketFu::Packet.parse p
	if pkt.is_ip?
		next if pkt.ip_saddr == PacketFu::Utils.ifconfig[:ip_saddr]
		if credit_card? pkt
			inc_num += 1
			print_inc inc_num, "Credit card leaked in the clear", pkt
		end
		if pkt.proto.last == "TCP" && pkt.tcp_flags.to_i == 0
			inc_num += 1
			print_inc inc_num, "NULL scan is detected", pkt		
		elsif pkt.proto.last == "TCP" && pkt.tcp_flags.urg.to_i == 1 && pkt.tcp_flags.psh.to_i == 1 && pkt.tcp_flags.fin.to_i == 1
			inc_num += 1
			print_inc inc_num, "XMAS scan is detected", pkt
		end
	end
end
cap.show_live()
end

def print_inc_wlog(inc_num, attack_type, sender, payload)
	print "#{inc_num}. ALERT: #{attack_type} is detected from #{sender} (HTTP) (#{payload})\n"
end

def analyze_log(wlog)
	inc_num = 0
	wlog.each do |line|
		if /Nmap/.match(line) != nil
			inc_num += 1
			print_inc_wlog inc_num, "NMAP scan", /\s/.match(line).pre_match, /".*?"/.match(line).to_s
		end
		if /HTTP/.match(line) != nil && /".*?"\s4\d{2}/.match(line) != nil
			inc_num += 1
			print_inc_wlog inc_num, "HTTP error", /\s/.match(line).pre_match, /".*?"/.match(line).to_s
		end
		if /(\\x\w{1,4}){3,}/.match(line) != nil
			inc_num += 1
			print_inc_wlog inc_num, "Shellcode", /\s/.match(line).pre_match, /"\\x.*?"/.match(line).to_s
		end
	end
end

# main code follows

if optionr == "-r" && weblog != nil
	wl = File.new(weblog)
	analyze_log wl
else
	live_stream
end
