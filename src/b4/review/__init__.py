# Re-export everything from the original review module
from b4.review._review import *  # noqa: F403
from b4.review._review import (
    _retrieve_messages, _get_lore_series,
    _collect_followups, _collect_reply_headers,
    _get_my_review, _ensure_my_review, _cleanup_review,
    _get_patch_state, _set_patch_state,
    _extract_patch_comments, _resolve_comment_positions,
    _reinsert_comments, _reinsert_all_comments,
    _clear_other_comments,
    _build_reply_from_comments, _ensure_trailers_in_body,
    _build_review_email,
    _integrate_agent_reviews,
    _prepare_review_session,
)

# Tell mypy these private symbols are intentionally re-exported
__all__ = [
    '_retrieve_messages', '_get_lore_series',
    '_collect_followups', '_collect_reply_headers',
    '_get_my_review', '_ensure_my_review', '_cleanup_review',
    '_get_patch_state', '_set_patch_state',
    '_extract_patch_comments', '_resolve_comment_positions',
    '_reinsert_comments', '_reinsert_all_comments',
    '_clear_other_comments',
    '_build_reply_from_comments', '_ensure_trailers_in_body',
    '_build_review_email',
    '_integrate_agent_reviews',
    '_prepare_review_session',
]
