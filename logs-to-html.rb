#!/usr/bin/env ruby
# elephantshark --no-bw | ./logs-to-html.rb > ~/Downloads/eslog.html

STDOUT.sync = true

puts %{<!DOCTYPE html>
<html><head><title>elephantshark log</title>
  <style>
    body { margin: 0; padding: 0; overflow-x: scroll; background: #002050; color: #eee; }
    pre { display: inline-block; padding: 10px 20px; margin: 0; font: 14px/1.4 'IBM Plex Mono', monospace; }
    .c33 { color: #ffee00; }
    .c34 { color: #0044ff; }
    .c35 { color: #00dddd; }
    .c36 { color: #ff44ff; }
  </style>
</head><body><pre>}

begin
  ARGF.each do |raw|
    puts raw.chomp
      .gsub(/[<>"']/, { '<' => '&lt;', '>' => '&gt;', '"' => '&quot;', "'" => '&apos;' })
      .gsub(/\033\[(\d+)m(.*?)\033\[0m/, '<span class="c\1">\2</span>')
  end
ensure
  puts %{</pre></body></html>}
end
