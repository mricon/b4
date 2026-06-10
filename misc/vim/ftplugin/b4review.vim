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

" Parse the count out of a skip-marker line; -1 if the line isn't a marker.
function! s:B4MarkerCount(line) abort
  let l:m = matchlist(a:line, '^> \[ \.\.\. \(\d\+\) lines skipped \.\.\. \]$')
  return empty(l:m) ? -1 : str2nr(l:m[1])
endfunction

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
" diff lines were removed.  Any skip markers directly adjacent to the range
" (above or below) are absorbed and their counts folded in, so consecutive
" trims collapse into one marker rather than stacking up.
function! s:B4ReplaceWithMarker(a, b) abort
  let l:a = a:a
  let l:b = a:b
  while l:a > 1 && s:B4MarkerCount(getline(l:a - 1)) >= 0
    let l:a -= 1
  endwhile
  while l:b < line('$') && s:B4MarkerCount(getline(l:b + 1)) >= 0
    let l:b += 1
  endwhile
  " Each quoted diff line counts as one; an absorbed marker contributes the
  " number it already represents.
  let l:c = 0
  for l:i in range(l:a, l:b)
    let l:t = getline(l:i)
    let l:mc = s:B4MarkerCount(l:t)
    if l:mc >= 0
      let l:c += l:mc
    elseif l:t =~# '^>'
      let l:c += 1
    endif
  endfor
  execute l:a . ',' . l:b . 'delete _'
  call append(l:a - 1, printf('> [ ... %d lines skipped ... ]', l:c))
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

" Delete the diff hunks above the current one, collapsing them into one
" marker.  The upward walk stops at the file header (the ---/+++/diff --git
" lines) or at your last comment (a bare line), so the file header, the
" quoted commit message and any annotated context above are all preserved.
function! s:B4DeleteHunksBefore() abort
  let l:hdr = s:B4HunkHeaderAbove()
  if l:hdr == 0
    echohl WarningMsg | echo 'b4: not inside a hunk' | echohl None
    return
  endif
  let l:fhdr = '^> \(diff --git \|--- \|+++ \)'
  if l:hdr == 1 || getline(l:hdr - 1) !~# '^[>|]' || getline(l:hdr - 1) =~# l:fhdr
    echohl WarningMsg | echo 'b4: no hunks to trim above this one' | echohl None
    return
  endif
  let l:top = l:hdr - 1
  while l:top > 1
        \ && getline(l:top - 1) =~# '^[>|]'
        \ && getline(l:top - 1) !~# l:fhdr
    let l:top -= 1
  endwhile
  call s:B4ReplaceWithMarker(l:top, l:hdr - 1)
  call cursor(l:top + 1, 1)
endfunction

nnoremap <silent> <buffer> <Plug>(B4DeleteHunk)        :call <SID>B4DeleteHunk()<CR>
nnoremap <silent> <buffer> <Plug>(B4DeleteHunksBefore) :call <SID>B4DeleteHunksBefore()<CR>
command! -buffer B4DelHunk        call <SID>B4DeleteHunk()
command! -buffer B4DelHunksBefore call <SID>B4DeleteHunksBefore()
" <nowait> so these fire immediately: without it, if another (global) plugin
" maps a longer <LocalLeader> sequence -- e.g. AlignMaps' \Htd shares our \H
" prefix -- vim would block for 'timeoutlen' waiting for the next key.
if empty(maparg('<LocalLeader>h', 'n'))
  nmap <buffer> <nowait> <LocalLeader>h <Plug>(B4DeleteHunk)
endif
if empty(maparg('<LocalLeader>H', 'n'))
  nmap <buffer> <nowait> <LocalLeader>H <Plug>(B4DeleteHunksBefore)
endif

" ---------------------------------------------------------------------------
" Adopting an external reviewer's comment as your own.
"
" Agent and other reviewers' comments are loaded as read-only "| "-quoted
" blocks, which b4 drops when it sends.  Adopting one strips the | prefix so
" the text becomes a bare comment of your own (which b4 keeps and sends), and
" drops the reviewer attribution and "via:" provenance lines, leaving just the
" comment text in place under the same diff line, ready for you to edit.
"
"   <LocalLeader>a   adopt the | comment block under the cursor
"
" Also available as :B4Adopt and <Plug>(B4AdoptComment).

function! s:B4AdoptComment() abort
  if getline('.') !~# '^|'
    echohl WarningMsg | echo 'b4: not on a | comment line' | echohl None
    return
  endif
  let l:s = line('.')
  while l:s > 1 && getline(l:s - 1) =~# '^|' | let l:s -= 1 | endwhile
  let l:e = line('.')
  while l:e < line('$') && getline(l:e + 1) =~# '^|' | let l:e += 1 | endwhile
  " Strip the | prefix from the comment text, dropping the "| Name <addr>:"
  " attribution header and the "| via: ..." provenance line.
  let l:out = []
  for l:i in range(l:s, l:e)
    let l:t = getline(l:i)
    if l:t =~# '^| .*>:$' || l:t =~# '^| via: '
      continue
    endif
    let l:out += [substitute(l:t, '^| \=', '', '')]
  endfor
  while len(l:out) && l:out[0] ==# '' | call remove(l:out, 0) | endwhile
  while len(l:out) && l:out[-1] ==# '' | call remove(l:out, -1) | endwhile
  execute l:s . ',' . l:e . 'delete _'
  call append(l:s - 1, l:out)
  call cursor(l:s, 1)
endfunction

nnoremap <silent> <buffer> <Plug>(B4AdoptComment) :call <SID>B4AdoptComment()<CR>
command! -buffer B4Adopt call <SID>B4AdoptComment()
if empty(maparg('<LocalLeader>a', 'n'))
  nmap <buffer> <nowait> <LocalLeader>a <Plug>(B4AdoptComment)
endif

let b:undo_ftplugin = get(b:, 'undo_ftplugin', '')
      \ . '| setlocal textwidth<'
      \ . '| silent! autocmd! b4review_wrap * <buffer>'
      \ . '| silent! delcommand B4DelHunk'
      \ . '| silent! delcommand B4DelHunksBefore'
      \ . '| silent! delcommand B4Adopt'
      \ . '| silent! nunmap <buffer> <Plug>(B4DeleteHunk)'
      \ . '| silent! nunmap <buffer> <Plug>(B4DeleteHunksBefore)'
      \ . '| silent! nunmap <buffer> <Plug>(B4AdoptComment)'
