# Developer Diary

## Found issues

### [27th June 2025]

    

## Invariants

- If traversing from the start of the heap, it's guaranteed that I'm traversing block by block and not some random data.

- Since `grow_heap` is called by the traverser, I'm confident that it will get called with the correct last header.