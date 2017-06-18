require 'nokogiri'

risk = {0=>"None", 1=>"Low", 2=>"Medium", 3=>"High", 4=>"Critical"}
risk_factor = 0

USAGE = <<ENDUSAGE
Usage:
   nessus_ssl_parser.rb [options] nessus_file_location
ENDUSAGE

HELP = <<ENDHELP
   -h, --help       Show this help.
   -v, --version    Show the version number.
   -l, --logfile    Specify the filename to log to.
   -i, --isseus     List by issue.
   -ip              List by IP 
   -r, --risk       Include all risk levels above X (All = 0, Low = 1, Medium = 2, High = 3, Critical = 4)
   -V. --verbose    Output in verbose mode. (ONLY IMPLEMENTED FOR ISSUE LIST)
ENDHELP

VERSION = <<ENDVERSION
Version: nessue_ssl_parser 1.0
ENDVERSION

ARGS = { :help=>false, :version=>false, :issue=>false, :ip=>false, :risk=>0, :verbose=>false}
UNFLAGGED_ARGS = [ :directory ]              # Bare arguments (no flag)
next_arg = UNFLAGGED_ARGS.first
files = Array.new
ARGV.each do |arg|
  case arg
    when '-h','--help'      then ARGS[:help]      = true
    when '-v','--version'   then ARGS[:version]   = true
    when '-i','--issues'    then ARGS[:issue]     = true
    when '-ip'              then ARGS[:ip]        = true
    when '-V','--verbose'   then ARGS[:verbose]   = true
    when '-r','--risk'      then next_arg = :risk
    when '-l','--logfile'   then next_arg = :logfile
    else
    	if File.exist?(arg)
			files.push(arg)
		end
	    if next_arg
	    	ARGS[next_arg] = arg
	      	UNFLAGGED_ARGS.delete( next_arg )
	    end
	    next_arg = UNFLAGGED_ARGS.first
  end
end

if ARGS[:help] or !ARGS[:directory] and !ARGS[:version]
	puts USAGE unless ARGS[:version]
	puts HELP if ARGS[:help]
	exit
end

if ARGS[:version] == true
	puts VERSION
end

if ARGS[:risk]
	risk_factor = ARGS[:risk]
end

if ARGS[:logfile]
	$stdout.reopen( ARGS[:logfile], "w" )
	$stdout.sync = true
	$stderr.reopen( $stdout )
end

#list by ip
if ARGS[:ip]
	ip_list = Hash.new
	ip_final = Hash.new
	files.each_with_index do|a, i|
		doc = File.open(a)
	  	doc = Nokogiri::XML(doc)
	  	doc.xpath('//ReportHost').each_with_index do |ip, a|
	  		ip_list[[a,0]] = " * #{ip.attr('name')}"
	  		ip.xpath('ReportItem').each do |thing|
			  	content = thing.at_xpath('plugin_name').content
			  	if content.start_with? "SSL "
			  		risk.each_with_index do |risk, key|
			  			if risk.include?(thing.at_xpath('risk_factor').content) and key.to_i >= risk_factor.to_i
			  				if ip_list[[a,1]] == nil
			  					ip_list[[a,1]] = ""
			  				end
			  				if !ip_list[[a,1]].include? thing.at_xpath('plugin_name').content 
			  					ip_list[[a,1]] = "#{ip_list[[a,1]]}" + "  * #{thing.at_xpath('plugin_name').content}\n"
			  					#Add verbose functionality here
			  				end
			  			end
			  		end
		  		end
		  	end
	  	end
	end 
	chopper = 0
	while chopper < ip_list.length
		if ip_list[[chopper,1]]
			ip_final[[chopper,0]] = ip_list[[chopper,0]]
			ip_final[[chopper,1]] = ip_list[[chopper,1]]
		end
		chopper = chopper + 1
	end
	ip_final = ip_final.values
	puts "\n--------------ISSUES LISTED VIA IP-----------------"
	ip_final.each { |x| puts x }
	puts "---------------------------------------------------\n"
end

#list by issue
if ARGS[:issue]
	issue_list = []
	hold = ""
	files.each_with_index do|a, i|
		doc = File.open(a)
	  	doc = Nokogiri::XML(doc)
	  	doc.xpath('//ReportItem').each_with_index do |i, a|
  			content = i.at_xpath('plugin_name').content
  			if content.start_with? "SSL "
  				risk.each_with_index do |risk, key|
			  		if risk.include?(i.at_xpath('risk_factor').content) and key.to_i >= risk_factor.to_i
			  			if !issue_list.include?(i.at_xpath('plugin_name').content)
			  				issue_list.push(i.at_xpath('plugin_name').content)
			  			end
			  		end
			  	end
	  		end
	  	end
	  	doc.xpath('//ReportHost').each_with_index do |ip, a|
	  		host = "#{ip.attr('name')}"
	  		ip.xpath('ReportItem').each do |issue|
	  			if issue.at_xpath('plugin_name').content.start_with? "SSL "
		  			issue_list.each_with_index do |value, key|
			  			if value.include?(issue.at_xpath('plugin_name').content) and !value.include?(host)
			  				issue_list[key] = "#{issue_list[key]}\n  * #{host}" 
			  				############################################################## Verbose Functionality
				  			if ARGS[:verbose]	
				  				if issue.at_xpath('plugin_output')
				  					hold = issue.at_xpath('plugin_output').content
				  					hold = hold.split(" ")
					  				hold.each_with_index do |value1, key1|
					  					value1 = value1.to_s
					  					if value1.include?("-") and value1.length > 1 and !value1.include?("Orga") and !value1.include?("Country") and !value1.include?("Vali") and !value1.include?("bit") and !value1.include?("Sub") and !value1.include?("Issu") and !value1.include?("Sig") and !value1.include?("=") and !value1.include?("Comm")
					  						issue_list[key] = "#{issue_list[key]}\n   * #{value1}"
					  					end
					  				end
					  			end
					  		end
			  				############################################################## Verbose Functionality
			  			end
			  		end
	  			end
	  		end
	  	end
	end
	issue_list.each_with_index do |value, key|
		issue_list[key] = " * #{issue_list[key]}"
	end
	puts "\n--------------ISSUES LISTED VIA ISSUE-------------"
	puts issue_list
	puts "---------------------------------------------------\n"
end













