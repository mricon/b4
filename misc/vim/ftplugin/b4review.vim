" Vim ftplugin for b4 review editor files
" Prevents auto-wrapping of quoted diff lines while still allowing
" wrapping on the reviewer's own comment lines.

" Dynamically toggle textwidth based on cursor position: quoted (>),
" external (|), and instruction (#) lines get textwidth=0 so vim
" never auto-wraps them; comment lines use the original textwidth.
let b:b4review_textwidth = &l:textwidth ? &l:textwidth : 72

augroup b4review_wrap
  autocmd! * <buffer>
  autocmd CursorMovedI <buffer> call s:B4ReviewUpdateWrap()
augroup END

function! s:B4ReviewUpdateWrap() abort
  let line = getline('.')
  if line =~# '^\(>\||\|#\)'
    if &l:textwidth != 0
      setlocal textwidth=0
    endif
  else
    if &l:textwidth != b:b4review_textwidth
      let &l:textwidth = b:b4review_textwidth
    endif
  endif
endfunction
