"""
Ouroboros Persona System for AI Offensive AI

Implements strict instruction engineering for professional pentesting AI persona.
"""
from .persona_engine import PersonaEngine, PersonaConfig
from .instruction_engine import InstructionEngine
from .constraint_validator import ConstraintValidator
from .output_formatter import OutputFormatter

__all__ = ['PersonaEngine', 'PersonaConfig', 'InstructionEngine', 'ConstraintValidator', 'OutputFormatter']