# ExcelSheetProtection
Snippet to show Excel Sheetprotection Hashing algorithm

I worked for days trying to figure out how Excel do the sheetprotection. 

I found this comment on Stackoverflow.com: 
https://stackoverflow.com/questions/10694174/implement-ecma-376-sheetprotection-hashing-algorithm-in-ruby

That made me try it out. And I can confirm that https://stackoverflow.com/users/6726446/js441 solution worked. 

I created a new Workbook in Excel using Microsoft Excel 365. I protected the sheet using the password "dole". 
I then renamed the extention of the Excel fil eto ".zip", and unpacked the content. 
The file /xl/worksheets/sheet1.xml, have this tag near the bottom. 

```
<sheetProtection algorithmName="SHA-512"
hashValue="TxexuSWgkCxqVnKSnRLh73n4sSp/GEGMXK09Hk3Qq/+mLXCcCdShsmSbXmVYmsOyLs9vXF7s3tZQQQAGdG/9kA=="
saltValue="HwUHlVDHY2tAT5VGdF/hWw==" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
```

Now that I have a Salt and the password, I can try out algorithms to produce the same hash, and that I did. 

The execution of the snippet shows this output: 
```
Reproduced Hash: TxexuSWgkCxqVnKSnRLh73n4sSp/GEGMXK09Hk3Qq/+mLXCcCdShsmSbXmVYmsOyLs9vXF7s3tZQQQAGdG/9kA==
Match with Excel's hash!
Program ended with exit code: 0
```




