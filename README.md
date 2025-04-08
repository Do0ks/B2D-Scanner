# Just a injectable Memory Scanner.
![Demo](https://media3.giphy.com/media/v1.Y2lkPTc5MGI3NjExanRid3dhaGRva2Vya3JkMGNraGxyb296a3dwYmRmODlobGxvcnRvOSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/fRjngW7wuOJPj57x2K/giphy.gif)

Download DLL Injector here: https://github.com/Do0ks/Injector

<b><u>Discription:</u></b>

This is extreamly helpful and powerful if you know of a solid base address with some good pointers, this tool will find the dynamic address along with the missing pointers quicly giving you a solid pointer chain. I made this for the things I couldn't find in UEDumper, but could be applied to other methods.

<b><u>Updates:</u></b>
<details>
  
- Added functions to extract the most-significant hex digit from an address and only follow pointers of first hex digit that of the base or dynamic address if applicable.

- Addad a check to ensure that only pointers with the same hex digit count as the expected pointer chain (from the base/dynamic addresses) are followed.

- Combined the above conditions with pointer readability checks to narrow the scan to relevant pointer chains.  
This should help reduce scan time while only following relevant pointer paths. To further speed up scanning time, if known, adjust the MAX_OFFSET and MAX_SUBOFFSET
</details>
