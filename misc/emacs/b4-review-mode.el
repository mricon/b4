;;; b4-review-mode.el --- Major mode for b4 review editor  -*- lexical-binding: t; -*-

;; Format: > quoted diff/message, | external comments, unquoted = own comments

;;; Commentary:

;; Provides syntax highlighting for the b4 review reply format.
;; Quoted diff lines (> prefix) are highlighted with diff colours,
;; external reviewer comments (| prefix) are dimmed, and the
;; maintainer's own comments use the default face.
;;
;; To install, add to your init.el:
;;
;;   (load "/path/to/b4/misc/emacs/b4-review-mode.el")
;;
;; The mode is automatically activated for *.b4-review.eml files.

;;; Code:

(defgroup b4-review nil
  "Major mode for b4 review editor."
  :group 'tools)

(defcustom b4-review-skipped-marker t
  "Master switch for the \"NN lines skipped\" marker feature.
When non-nil (the default), the `b4-review-delete-hunk' /
`b4-review-delete-hunks-before' commands and -- if `b4-review-auto-marker'
is also on -- the automatic marker on a plain delete are available.  Set
to nil to turn the whole feature off, leaving only syntax highlighting and
`b4-review-adopt-comment'."
  :type 'boolean
  :group 'b4-review)

(defcustom b4-review-auto-marker nil
  "When non-nil, a plain delete of quoted lines leaves a skip marker.
A line-wise delete with ordinary editing commands (kill-whole-line, evil
`dd', killing a region of whole lines ...) that removes quoted diff lines
drops the same \"[ ... NN lines skipped ... ]\" breadcrumb the trimming
commands leave, counting only the quoted (>) lines that were removed.

Off by default: reacting to every edit is invasive and can surprise
people, so out of the box only the deliberate `b4-review-delete-hunk' /
`b4-review-delete-hunks-before' commands leave a marker.  Requires
`b4-review-skipped-marker' to also be on."
  :type 'boolean
  :group 'b4-review)

(defvar-local b4-review--pending-delete nil
  "Whole quoted lines about to be deleted, as a cons of (BEG . TEXT).
Set by `b4-review--before-change' and consumed by
`b4-review--after-change'; nil when the pending change is not a
whole-line deletion worth a breadcrumb.")

(defface b4-review-quote-prefix
  '((t :foreground "dark cyan"))
  "Face for the leading \"> \" prefix."
  :group 'b4-review)

(defface b4-review-quoted
  '((t :foreground "dark cyan"))
  "Face for plain quoted lines (commit message, context)."
  :group 'b4-review)

(defface b4-review-diff-add
  '((t :foreground "green"))
  "Face for quoted diff additions (> +)."
  :group 'b4-review)

(defface b4-review-diff-remove
  '((t :foreground "red"))
  "Face for quoted diff removals (> -)."
  :group 'b4-review)

(defface b4-review-diff-hunk
  '((t :foreground "cyan" :weight bold))
  "Face for quoted diff hunk headers (> @@)."
  :group 'b4-review)

(defface b4-review-diff-file
  '((t :weight bold))
  "Face for quoted diff file headers."
  :group 'b4-review)

(defface b4-review-diff-file-a
  '((t :foreground "red" :weight bold))
  "Face for quoted --- file paths."
  :group 'b4-review)

(defface b4-review-diff-file-b
  '((t :foreground "green" :weight bold))
  "Face for quoted +++ file paths."
  :group 'b4-review)

(defface b4-review-ext-header
  '((t :foreground "yellow" :weight bold))
  "Face for external comment attribution header (| Name <email>:)."
  :group 'b4-review)

(defface b4-review-ext-comment
  '((t :foreground "dark cyan"))
  "Face for external comment body lines (| text)."
  :group 'b4-review)

(defface b4-review-ext-via
  '((t :foreground "yellow" :slant italic))
  "Face for external comment provenance (| via: ...)."
  :group 'b4-review)

(defface b4-review-instruction
  '((t :foreground "dark cyan" :slant italic))
  "Face for instruction lines (# ...)."
  :group 'b4-review)

(defvar b4-review-font-lock-keywords
  `(
    ;; Order matters — earlier rules take priority in Emacs font-lock

    ;; Quoted diff lines — specific patterns first
    ("^\\(> \\)\\(\\+\\+\\+ .*\\)$"
     (1 'b4-review-quote-prefix)
     (2 'b4-review-diff-file-b))
    ("^\\(> \\)\\(--- .*\\)$"
     (1 'b4-review-quote-prefix)
     (2 'b4-review-diff-file-a))
    ("^\\(> \\)\\(diff --git .*\\)$"
     (1 'b4-review-quote-prefix)
     (2 'b4-review-diff-file))
    ("^\\(> \\)\\(@@.*\\)$"
     (1 'b4-review-quote-prefix)
     (2 'b4-review-diff-hunk))
    ("^\\(> \\)\\(\\+.*\\)$"
     (1 'b4-review-quote-prefix)
     (2 'b4-review-diff-add))
    ("^\\(> \\)\\(-.*\\)$"
     (1 'b4-review-quote-prefix)
     (2 'b4-review-diff-remove))
    ("^\\(> \\)\\(index \\|new file\\|deleted file\\|old mode\\|new mode\\|similarity\\|rename\\|copy\\)\\(.*\\)$"
     (1 'b4-review-quote-prefix)
     (2 'b4-review-diff-file)
     (3 'b4-review-diff-file))

    ;; Plain quoted lines (catch-all for > lines not matched above)
    ("^\\(> \\)\\(.*\\)$"
     (1 'b4-review-quote-prefix)
     (2 'b4-review-quoted))
    ("^>$" (0 'b4-review-quoted))

    ;; External reviewer comments (| prefix) — specific first
    ("^| via: .*$" (0 'b4-review-ext-via))
    ("^| .+>:$" (0 'b4-review-ext-header))
    ("^| .*$" (0 'b4-review-ext-comment))
    ("^|$" (0 'b4-review-ext-comment))

    ;; Instruction lines
    ("^#.*$" (0 'b4-review-instruction))
    )
  "Font-lock keywords for `b4-review-mode'.")

(defun b4-review--auto-fill ()
  "Auto-fill only on the reviewer's own comment lines.
Quoted (> ), external (|), and instruction (#) lines are left alone."
  (let ((prefix (buffer-substring-no-properties
                  (line-beginning-position)
                  (min (+ (line-beginning-position) 2) (line-end-position)))))
    (unless (or (string-prefix-p ">" prefix)
                (string-prefix-p "|" prefix)
                (string-prefix-p "#" prefix))
      (do-auto-fill))))

;;; Trimming and adopting -----------------------------------------------------
;;
;; b4 itself only drops the quoted diff left below your last comment when it
;; sends.  These commands let you prune irrelevant hunks interactively as you
;; read, leaving a "[ ... NN lines skipped ... ]" marker where context was
;; removed, and adopt an external reviewer's "| " comment as your own.  It all
;; happens in the buffer, so what you see is what gets sent; undo restores it.
;;
;; Beyond the explicit commands, a plain line-wise delete of quoted material
;; with whatever editing commands you already use leaves the same marker
;; automatically (see `b4-review-auto-marker').  Only the quoted diff (>)
;; lines you removed are counted; your own notes and "| " external comments
;; are not, and a delete that removed none of the former leaves no marker.
;; The count is a reading aid, not something b4 parses, so being off by a
;; line or two is harmless.

(defconst b4-review--skip-re
  "^> \\[ \\.\\.\\. \\([0-9]+\\) lines skipped \\.\\.\\. \\]$"
  "Match a quoted skip marker; group 1 captures its line count.")

(defun b4-review--marker-count ()
  "Return the count in the skip marker on the current line, or nil."
  (save-excursion
    (beginning-of-line)
    (when (looking-at b4-review--skip-re)
      (string-to-number (match-string 1)))))

(defun b4-review--hunk-header-pos ()
  "Return the position of the `> @@' header at or above point, or nil.
Returns nil if a file header is reached first, meaning point is not
inside a hunk."
  (save-excursion
    (beginning-of-line)
    (catch 'done
      (while t
        (cond
         ((looking-at-p "^> @@ ") (throw 'done (point)))
         ((looking-at-p "^> \\(diff --git \\|--- \\|\\+\\+\\+ \\)")
          (throw 'done nil))
         ((bobp) (throw 'done nil))
         (t (forward-line -1)))))))

(defun b4-review--replace-lines-with-marker (beg-pos end-pos)
  "Replace whole lines from BEG-POS through END-POS with one skip marker.
Any skip markers directly adjacent to the range (above or below) are
absorbed and their counts folded in, so consecutive trims collapse into
one marker rather than stacking up.  Point is left just after the marker."
  (let ((beg (save-excursion (goto-char beg-pos) (line-beginning-position)))
        (end (save-excursion (goto-char end-pos) (forward-line 1) (point)))
        (count 0)
        ;; This is a deliberate edit, not a user delete: keep the change
        ;; hooks (and so the auto-marker) from reacting to our own work.
        (inhibit-modification-hooks t))
    ;; Absorb consecutive markers immediately above and below the range.
    (save-excursion
      (goto-char beg)
      (while (and (not (bobp))
                  (save-excursion (forward-line -1) (b4-review--marker-count)))
        (forward-line -1)
        (setq beg (point))))
    (save-excursion
      (goto-char end)
      (while (and (< (point) (point-max)) (b4-review--marker-count))
        (forward-line 1)
        (setq end (point))))
    ;; Each quoted diff line counts as one; an absorbed marker contributes
    ;; the number it already represents.
    (save-excursion
      (goto-char beg)
      (while (< (point) end)
        (let ((mc (b4-review--marker-count)))
          (cond (mc (setq count (+ count mc)))
                ((looking-at-p "^>") (setq count (1+ count)))))
        (forward-line 1)))
    (delete-region beg end)
    (goto-char beg)
    (insert (format "> [ ... %d lines skipped ... ]\n" count))))

(defun b4-review--marker-count-in (line)
  "Return the skip-marker count in string LINE, or nil."
  (when (string-match b4-review--skip-re line)
    (string-to-number (match-string 1 line))))

(defun b4-review--place-marker (pos base)
  "Insert one skip marker for BASE quoted lines at POS.
POS is a line beginning where a just-deleted block was.  Any skip markers
now directly above or below that point are absorbed and their counts
folded in, mirroring `b4-review--replace-lines-with-marker'.  This is its
already-deleted counterpart: the lines are gone, so we only place and
coalesce the marker rather than counting a live range."
  (let ((count base)
        (inhibit-modification-hooks t))
    (save-excursion
      (goto-char pos)
      ;; Absorb markers now sitting at the deletion point and below it.
      (let (mc)
        (while (setq mc (b4-review--marker-count))
          (setq count (+ count mc))
          (delete-region (point)
                         (min (point-max) (1+ (line-end-position))))))
      ;; Absorb markers directly above it, walking the insertion point up.
      (while (and (not (bobp))
                  (save-excursion (forward-line -1) (b4-review--marker-count)))
        (forward-line -1)
        (setq count (+ count (b4-review--marker-count)))
        (delete-region (point) (progn (forward-line 1) (point))))
      (insert (format "> [ ... %d lines skipped ... ]\n" count)))))

(defun b4-review--before-change (beg end)
  "Stash whole quoted lines about to be deleted for `b4-review--after-change'.
Only a removal that starts at a line beginning and spans complete lines
qualifies, mirroring vim's line-wise-only rule."
  (setq b4-review--pending-delete nil)
  (when (and b4-review-auto-marker (> end beg))
    (let ((text (buffer-substring-no-properties beg end)))
      (when (and (save-excursion (goto-char beg) (bolp))
                 (or (eq (char-before end) ?\n) (= end (point-max))))
        (setq b4-review--pending-delete (cons beg text))))))

(defun b4-review--after-change (beg end len)
  "Drop a skip marker if a stashed whole-line delete of quoted lines just ran.
A pure deletion inserts nothing (BEG = END) and reports LEN > 0.  Only the
quoted diff (>) lines are counted; an absorbed marker folds in the number
it already stood for, and a delete with no quoted lines leaves no marker."
  (when (and b4-review--pending-delete
             (= beg end)
             (> len 0))
    (let ((pos (car b4-review--pending-delete))
          (text (cdr b4-review--pending-delete)))
      (setq b4-review--pending-delete nil)
      (when (= beg pos)
        (let ((count 0) (hascode nil))
          (dolist (line (split-string text "\n"))
            (let ((mc (b4-review--marker-count-in line)))
              (cond (mc (setq count (+ count mc)))
                    ((string-prefix-p ">" line)
                     (setq count (1+ count) hascode t)))))
          (when hascode
            (b4-review--place-marker pos count)))))))

(defun b4-review-delete-hunk ()
  "Delete the diff hunk under point, leaving a skip marker.
Removes the `> @@' header through the hunk's last quoted line, including
any of your comments interspersed within it."
  (interactive)
  (unless b4-review-skipped-marker
    (user-error "b4: skip-marker feature disabled (b4-review-skipped-marker)"))
  (let ((hdr (b4-review--hunk-header-pos)))
    (if (not hdr)
        (message "b4: not inside a hunk")
      (let ((last-quoted hdr))
        (save-excursion
          (goto-char hdr)
          (forward-line 1)
          (catch 'done
            (while (not (eobp))
              (cond
               ((looking-at-p "^> \\(@@ \\|diff --git \\)") (throw 'done nil))
               ((looking-at-p "^>") (setq last-quoted (point))))
              (forward-line 1))))
        (b4-review--replace-lines-with-marker hdr last-quoted)))))

(defun b4-review-delete-hunks-before ()
  "Delete the diff hunks above the current one, leaving a skip marker.
The upward walk stops at the file header (the ---/+++/diff --git lines)
or at your last comment, so the file header, the quoted commit message
and any annotated context above are all preserved."
  (interactive)
  (unless b4-review-skipped-marker
    (user-error "b4: skip-marker feature disabled (b4-review-skipped-marker)"))
  (let ((hdr (b4-review--hunk-header-pos))
        (fhdr "^> \\(diff --git \\|--- \\|\\+\\+\\+ \\)"))
    (if (not hdr)
        (message "b4: not inside a hunk")
      (let (top bottom)
        (save-excursion
          (goto-char hdr)
          (unless (bobp)
            (forward-line -1)
            (when (and (looking-at-p "^[>|]") (not (looking-at-p fhdr)))
              (setq bottom (point))
              (while (and (not (bobp))
                          (save-excursion
                            (forward-line -1)
                            (and (looking-at-p "^[>|]")
                                 (not (looking-at-p fhdr)))))
                (forward-line -1))
              (setq top (point)))))
        (if (not bottom)
            (message "b4: no hunks to trim above this one")
          (b4-review--replace-lines-with-marker top bottom))))))

(defun b4-review-adopt-comment ()
  "Adopt the external (|) comment block under point as your own.
Strips the leading `| ' so the text becomes a bare comment of your own,
and drops the reviewer attribution and `via:' provenance lines, leaving
the comment text in place under the same diff line, ready to edit."
  (interactive)
  (beginning-of-line)
  (if (not (looking-at-p "^|"))
      (message "b4: not on a | comment line")
    (let (beg end (lines '())
          ;; A deliberate edit: keep the auto-marker from reacting to it.
          (inhibit-modification-hooks t))
      (save-excursion
        (while (and (not (bobp))
                    (save-excursion (forward-line -1) (looking-at-p "^|")))
          (forward-line -1))
        (setq beg (point))
        (while (looking-at-p "^|")
          (let ((l (buffer-substring-no-properties
                    (line-beginning-position) (line-end-position))))
            (unless (or (string-match-p "^| .*>:$" l)
                        (string-match-p "^| via: " l))
              (push (replace-regexp-in-string "^| ?" "" l) lines)))
          (forward-line 1))
        (setq end (point)))
      (setq lines (nreverse lines))
      (while (and lines (string= (car lines) ""))
        (setq lines (cdr lines)))
      (while (and lines (string= (car (last lines)) ""))
        (setq lines (butlast lines)))
      (delete-region beg end)
      (goto-char beg)
      (when lines
        (insert (mapconcat #'identity lines "\n") "\n")))))

(defvar b4-review-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd "C-c C-k") #'b4-review-delete-hunk)
    (define-key map (kbd "C-c C-b") #'b4-review-delete-hunks-before)
    (define-key map (kbd "C-c C-a") #'b4-review-adopt-comment)
    map)
  "Keymap for `b4-review-mode'.")

;;;###autoload
(define-derived-mode b4-review-mode text-mode "b4-review"
  "Major mode for editing b4 review replies."
  (setq font-lock-defaults '(b4-review-font-lock-keywords t))
  ;; Only auto-fill the reviewer's own comment lines — quoted diff
  ;; lines (> ), external comments (|), and instructions (#) must not
  ;; be reflowed or the parser cannot match them.
  (setq-local auto-fill-function #'b4-review--auto-fill)
  ;; Disable spell-checking on quoted and external lines
  (setq-local flyspell-generic-check-word-predicate
              #'b4-review--flyspell-check-p)
  ;; Leave a skip marker when quoted diff is deleted with ordinary editing
  ;; commands, the same breadcrumb the trimming commands drop.  before-change
  ;; captures the soon-to-be-deleted text (so we can count its quoted lines)
  ;; and after-change confirms it was a pure deletion before placing the
  ;; marker.  Both run inside the deleting command, so a single undo reverts
  ;; the delete and the marker together.  Opt-in (see `b4-review-auto-marker'):
  ;; with it off we install no change hooks at all, so nothing reacts to edits.
  (when (and b4-review-skipped-marker b4-review-auto-marker)
    (add-hook 'before-change-functions #'b4-review--before-change nil t)
    (add-hook 'after-change-functions #'b4-review--after-change nil t)))

(defun b4-review--flyspell-check-p ()
  "Return non-nil if the word at point should be spell-checked.
Only check unquoted, non-external, non-instruction lines."
  (let ((line (buffer-substring-no-properties
               (line-beginning-position) (line-end-position))))
    (not (or (string-prefix-p ">" line)
             (string-prefix-p "|" line)
             (string-prefix-p "#" line)))))

;;;###autoload
(add-to-list 'auto-mode-alist '("\\.b4-review\\.eml\\'" . b4-review-mode))

(provide 'b4-review-mode)
;;; b4-review-mode.el ends here
