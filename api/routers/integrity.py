"""Forensic Integrity Router — Cryptographic Merkle Chains & Blast Radius."""

from fastapi import APIRouter
from database.db import get_events
from services.crypto_chain import build_investigation_hash_chain
from services.graph_analytics import calculate_blast_radius, compute_killchain_paths

router = APIRouter(prefix="/api/v1/investigations/{inv_id}", tags=["Forensic Integrity"])


@router.get("/chain")
def get_investigation_merkle_chain(inv_id: str):
    """
    Returns the cryptographic SHA-256 sequential hash chain and Merkle root verification.
    """
    events = get_events(inv_id)
    return build_investigation_hash_chain(events, inv_id)


@router.get("/blast-radius")
def get_investigation_blast_radius(inv_id: str):
    """
    Calculates enterprise blast radius percentage, compromised hosts, and kill-chain paths.
    """
    blast = calculate_blast_radius(inv_id)
    paths = compute_killchain_paths(inv_id)
    blast["killchain_paths"] = paths
    return blast
