" Vim syntax file for b4 review editor
" Format: > quoted diff/message, | external comments, unquoted = own comments

if exists('b:current_syntax')
  finish
endif

" The leading "> " prefix — always the same colour regardless of line type
syn match b4QuotePrefix   /^> / contained

" Plain quoted lines (commit message, context, etc.) — defined first
" so more specific patterns below take priority
syn match b4Quoted        /^> .*/ contains=b4QuotePrefix,@NoSpell
syn match b4QuotedEmpty   /^>$/

" Quoted diff lines (> prefix) — more specific, override b4Quoted
syn match b4DiffAdd       /^> +.*/ contains=b4QuotePrefix,@NoSpell
syn match b4DiffRemove    /^> -.*/ contains=b4QuotePrefix,@NoSpell
syn match b4DiffHunk      /^> @@ .*/ contains=b4QuotePrefix,@NoSpell
syn match b4DiffFile      /^> diff --git .*/ contains=b4QuotePrefix,@NoSpell
syn match b4DiffMeta      /^> \(index \|new file\|deleted file\|old mode\|new mode\|similarity\|rename\|copy\).*/ contains=b4QuotePrefix,@NoSpell
syn match b4DiffFileA     /^> --- .*/ contains=b4QuotePrefix,@NoSpell
syn match b4DiffFileB     /^> +++ .*/ contains=b4QuotePrefix,@NoSpell

" External reviewer comments (| prefix)
syn match b4ExtComment    /^| .*/ contains=@NoSpell
syn match b4ExtEmpty      /^|$/
syn match b4ExtHeader     /^| .\+:$/ contains=@NoSpell
syn match b4ExtVia        /^| via: .*/ contains=@NoSpell

" Instruction lines
syn match b4Instruction   /^#.*/ contains=@NoSpell

" Highlights — use sensible defaults, let colorscheme override
hi def b4QuotePrefix   ctermfg=darkcyan  guifg=#6272a4
hi def b4DiffAdd       ctermfg=green     guifg=#50fa7b
hi def b4DiffRemove    ctermfg=red       guifg=#ff5555
hi def b4DiffHunk      ctermfg=cyan      guifg=#8be9fd  cterm=bold gui=bold
hi def b4DiffFile      ctermfg=white     guifg=#f8f8f2  cterm=bold gui=bold
hi def b4DiffMeta      ctermfg=white     guifg=#f8f8f2  cterm=bold gui=bold
hi def b4DiffFileA     ctermfg=red       guifg=#ff5555  cterm=bold gui=bold
hi def b4DiffFileB     ctermfg=green     guifg=#50fa7b  cterm=bold gui=bold
hi def b4Quoted        ctermfg=darkcyan  guifg=#6272a4
hi def b4QuotedEmpty   ctermfg=darkcyan  guifg=#6272a4
hi def b4ExtHeader     ctermfg=yellow    guifg=#f1fa8c  cterm=bold gui=bold
hi def b4ExtComment    ctermfg=darkcyan  guifg=#6272a4
hi def b4ExtEmpty      ctermfg=darkcyan  guifg=#6272a4
hi def b4ExtVia        ctermfg=yellow    guifg=#f1fa8c  cterm=italic gui=italic
hi def b4Instruction   ctermfg=darkgray  guifg=#6272a4  cterm=italic gui=italic

let b:current_syntax = 'b4review'
