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
    ("^| .+:$" (0 'b4-review-ext-header))
    ("^| .*$" (0 'b4-review-ext-comment))
    ("^|$" (0 'b4-review-ext-comment))

    ;; Instruction lines
    ("^#.*$" (0 'b4-review-instruction))
    )
  "Font-lock keywords for `b4-review-mode'.")

;;;###autoload
(define-derived-mode b4-review-mode text-mode "b4-review"
  "Major mode for editing b4 review replies."
  (setq font-lock-defaults '(b4-review-font-lock-keywords t))
  ;; Disable spell-checking on quoted and external lines
  (setq-local flyspell-generic-check-word-predicate
              #'b4-review--flyspell-check-p))

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
