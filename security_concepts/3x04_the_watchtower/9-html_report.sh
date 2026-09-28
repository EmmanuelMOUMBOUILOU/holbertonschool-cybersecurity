#!/bin/bash
echo '<html><body><h1>Security Report</h1><table><tr><th>IP Address</th><th>Attempts</th></tr>' > $2
grep "Failed password" "$1" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -nr | head -5 | awk '{print "<tr><td>" $2 "</td><td>" $1 "</td></tr>"}' >> $2
echo '</table></body></html>' >> $2