# OCF Simulator


OCF Simulator determine OCF cache condition following execution of blktrace files.

# In this readme:

* [Source Code](#source-code)
* [Execution](#execution)

## Source Code

Source code structure required for compliation of ocf_sim:
 -- open-cas-linux (OpenCAS Linux)
    | 
    +-- casadm
    |
    +-- modules
    |   |
    |   + include
    |
    +-- ocf (Open CAS Framework)
        |
        + ocf_sim
  + is available in the official OCF GitHub repository:

~~~{.sh}
cd open-cas-linux/ocf/ocf_sim
make
~~~

## Execution

ocf_sim -t BLKPARSE_FILE [-c cahce_size] [-o {table|csv} [-O OUTFILE]] [-v] [-h]
