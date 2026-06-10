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

" ---------------------------------------------------------------------------
" Trimming quoted diff out of the outgoing reply.
"
" b4 itself only drops the quoted diff left below your last comment when it
" sends.  These mappings let you prune irrelevant hunks interactively as you
" read, leaving a "[ ... NN lines skipped ... ]" marker so it is obvious where
" context was elided.  It all happens in the buffer, so what you see is what
" gets sent -- and u undoes it.
"
"   <LocalLeader>h   delete the hunk under the cursor
"   <LocalLeader>H   delete the (uncommented) hunks above the current one
"
" Also available as :B4DelHunk / :B4DelHunksBefore and as the mappable
" <Plug>(B4DeleteHunk) / <Plug>(B4DeleteHunksBefore).

let s:skip_re = '^> \[ \.\.\. \d\+ lines skipped \.\.\. \]$'

" Line of the `> @@` hunk header at or above the cursor, or 0 if the cursor
" is not inside a hunk (a file header is reached first, or there is none).
function! s:B4HunkHeaderAbove() abort
  let l:n = line('.')
  while l:n >= 1
    let l:t = getline(l:n)
    if l:t =~# '^> @@ '
      return l:n
    endif
    if l:t =~# '^> diff --git \|^> --- \|^> +++ '
      return 0
    endif
    let l:n -= 1
  endwhile
  return 0
endfunction

" Delete lines [a, b] and leave a single marker reporting how many quoted
" diff lines were removed (pre-existing markers are not re-counted).
function! s:B4ReplaceWithMarker(a, b) abort
  let l:c = 0
  for l:i in range(a:a, a:b)
    let l:t = getline(l:i)
    if l:t =~# '^>' && l:t !~# s:skip_re
      let l:c += 1
    endif
  endfor
  execute a:a . ',' . a:b . 'delete _'
  call append(a:a - 1, printf('> [ ... %d lines skipped ... ]', l:c))
endfunction

" Delete the hunk under the cursor: its `> @@` header through its last
" quoted line, including any of your comments interspersed within it.
function! s:B4DeleteHunk() abort
  let l:hdr = s:B4HunkHeaderAbove()
  if l:hdr == 0
    echohl WarningMsg | echo 'b4: not inside a hunk' | echohl None
    return
  endif
  let l:last = l:hdr
  let l:n = l:hdr + 1
  while l:n <= line('$')
    let l:t = getline(l:n)
    if l:t =~# '^> @@ \|^> diff --git '
      break
    endif
    if l:t =~# '^>'
      let l:last = l:n
    endif
    let l:n += 1
  endwhile
  call s:B4ReplaceWithMarker(l:hdr, l:last)
endfunction

" Delete the quoted diff above the current hunk, up to your last comment
" (a bare line breaks the run), collapsing it into one marker.
function! s:B4DeleteHunksBefore() abort
  let l:hdr = s:B4HunkHeaderAbove()
  if l:hdr == 0
    echohl WarningMsg | echo 'b4: not inside a hunk' | echohl None
    return
  endif
  if l:hdr == 1 || getline(l:hdr - 1) !~# '^[>|]'
    echohl WarningMsg | echo 'b4: nothing to trim above' | echohl None
    return
  endif
  let l:top = l:hdr - 1
  while l:top > 1 && getline(l:top - 1) =~# '^[>|]'
    let l:top -= 1
  endwhile
  call s:B4ReplaceWithMarker(l:top, l:hdr - 1)
  call cursor(l:top + 1, 1)
endfunction

nnoremap <silent> <buffer> <Plug>(B4DeleteHunk)        :call <SID>B4DeleteHunk()<CR>
nnoremap <silent> <buffer> <Plug>(B4DeleteHunksBefore) :call <SID>B4DeleteHunksBefore()<CR>
command! -buffer B4DelHunk        call <SID>B4DeleteHunk()
command! -buffer B4DelHunksBefore call <SID>B4DeleteHunksBefore()
if empty(maparg('<LocalLeader>h', 'n'))
  nmap <buffer> <LocalLeader>h <Plug>(B4DeleteHunk)
endif
if empty(maparg('<LocalLeader>H', 'n'))
  nmap <buffer> <LocalLeader>H <Plug>(B4DeleteHunksBefore)
endif

let b:undo_ftplugin = get(b:, 'undo_ftplugin', '')
      \ . '| setlocal textwidth<'
      \ . '| silent! autocmd! b4review_wrap * <buffer>'
      \ . '| silent! delcommand B4DelHunk'
      \ . '| silent! delcommand B4DelHunksBefore'
      \ . '| silent! nunmap <buffer> <Plug>(B4DeleteHunk)'
      \ . '| silent! nunmap <buffer> <Plug>(B4DeleteHunksBefore)'
