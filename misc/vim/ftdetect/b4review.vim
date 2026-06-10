" Detect b4 review editor files by filename pattern.
" Force the filetype: vim's built-in rules detect *.eml as "mail" (the
" filetype mutt uses) before this ftdetect runs, and a polite setfiletype
" would be a no-op once that is set. Assigning filetype directly overrides
" it, since ftdetect autocommands fire after the built-in ones.
autocmd BufNewFile,BufRead *.b4-review.eml setlocal filetype=b4review
