# Just a injectable Memory Scanner.

### Updated to be a faster, better, more accurate Memory Scanner.
![B2D Scanner](https://github.com/user-attachments/assets/2ab4ea75-c867-4749-8393-f6d936a57e46)

Video Demos:
<Details>
  
https://github.com/user-attachments/assets/2686c5c3-cd16-44ba-a60f-648cdb5045c5

</Details>

 &bull; 
 <a href="https://discord.gg/7nGkqwdJhn">Discord</a>

<b>Discription:</b>

This is extreamly helpful and powerful if you know of a solid base address with some good pointers, this tool will find the dynamic address along with the missing pointers quicly giving you a solid pointer chain. I made this for the things I couldn't find in UEDumper, but could be applied to other methods.

<b><u>Updates:</u></b>
<details>

- Added dereferencing to base addresses.

- Added a check to ensure that only pointers with the same hex digit count as the expected pointer chain (from the base/dynamic addresses) are followed.

- Combined the above conditions with pointer readability checks to narrow the scan to relevant pointer chains.  
This should help reduce scan time while only following relevant pointer paths. To further speed up scanning time, if known, adjust the MAX_OFFSET and MAX_SUBOFFSET

</details>

Download DLL Injector here: https://github.com/Do0ks/Injector  
