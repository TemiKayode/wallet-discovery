"""
Data Quality Module with Advanced Validation Frameworks

This module provides comprehensive data quality validation for blockchain data,
including schema validation, business rule validation, and data profiling.
"""

import logging
import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import json
import re
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ValidationSeverity(Enum):
    """Validation severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class ValidationResult:
    """Represents the result of a validation check"""
    rule_name: str
    field_name: str
    severity: ValidationSeverity
    passed: bool
    message: str
    failed_count: int = 0
    total_count: int = 0


class DataQualityValidator:
    """Main data quality validator"""
    
    def __init__(self):
        self.validation_results = []
        
    def validate_data(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Run comprehensive data quality validation"""
        logger.info("Starting data quality validation")
        
        # Reset results
        self.validation_results = []
        
        # Run all validation checks
        self._validate_schema(df)
        self._validate_business_rules(df)
        self._validate_data_integrity(df)
        
        # Generate quality report
        report = self._generate_quality_report(df)
        
        logger.info(f"Data quality validation completed. Overall score: {report['quality_score']:.2%}")
        return report
        
    def _validate_schema(self, df: pd.DataFrame):
        """Validate data schema"""
        required_fields = ['address', 'amount', 'timestamp', 'chain']
        
        for field in required_fields:
            if field not in df.columns:
                self.validation_results.append(ValidationResult(
                    rule_name=f"Required Field: {field}",
                    field_name=field,
                    severity=ValidationSeverity.CRITICAL,
                    passed=False,
                    message=f"Required field '{field}' is missing",
                    total_count=len(df)
                ))
            else:
                self.validation_results.append(ValidationResult(
                    rule_name=f"Required Field: {field}",
                    field_name=field,
                    severity=ValidationSeverity.INFO,
                    passed=True,
                    message=f"Field '{field}' is present",
                    total_count=len(df)
                ))
                
    def _validate_business_rules(self, df: pd.DataFrame):
        """Validate business rules"""
        # Check for positive amounts
        if 'amount' in df.columns:
            negative_amounts = (df['amount'] < 0).sum()
            if negative_amounts > 0:
                self.validation_results.append(ValidationResult(
                    rule_name="Positive Amounts",
                    field_name="amount",
                    severity=ValidationSeverity.ERROR,
                    passed=False,
                    message=f"Found {negative_amounts} negative amounts",
                    failed_count=negative_amounts,
                    total_count=len(df)
                ))
            else:
                self.validation_results.append(ValidationResult(
                    rule_name="Positive Amounts",
                    field_name="amount",
                    severity=ValidationSeverity.INFO,
                    passed=True,
                    message="All amounts are positive",
                    total_count=len(df)
                ))
                
        # Check address format
        if 'address' in df.columns:
            invalid_addresses = 0
            for address in df['address']:
                if not self._is_valid_address(str(address)):
                    invalid_addresses += 1
                    
            if invalid_addresses > 0:
                self.validation_results.append(ValidationResult(
                    rule_name="Valid Address Format",
                    field_name="address",
                    severity=ValidationSeverity.ERROR,
                    passed=False,
                    message=f"Found {invalid_addresses} invalid addresses",
                    failed_count=invalid_addresses,
                    total_count=len(df)
                ))
            else:
                self.validation_results.append(ValidationResult(
                    rule_name="Valid Address Format",
                    field_name="address",
                    severity=ValidationSeverity.INFO,
                    passed=True,
                    message="All addresses have valid format",
                    total_count=len(df)
                ))
                
    def _validate_data_integrity(self, df: pd.DataFrame):
        """Validate data integrity"""
        # Check for missing values
        missing_values = df.isnull().sum().sum()
        total_cells = len(df) * len(df.columns)
        
        if missing_values > 0:
            missing_percentage = (missing_values / total_cells) * 100
            self.validation_results.append(ValidationResult(
                rule_name="Data Completeness",
                field_name="all",
                severity=ValidationSeverity.WARNING if missing_percentage < 10 else ValidationSeverity.ERROR,
                passed=missing_percentage < 5,
                message=f"Missing values: {missing_percentage:.2f}%",
                failed_count=missing_values,
                total_count=total_cells
            ))
        else:
            self.validation_results.append(ValidationResult(
                rule_name="Data Completeness",
                field_name="all",
                severity=ValidationSeverity.INFO,
                passed=True,
                message="No missing values found",
                total_count=total_cells
            ))
            
        # Check for duplicates
        duplicate_rows = df.duplicated().sum()
        if duplicate_rows > 0:
            duplicate_percentage = (duplicate_rows / len(df)) * 100
            self.validation_results.append(ValidationResult(
                rule_name="Data Uniqueness",
                field_name="all",
                severity=ValidationSeverity.WARNING if duplicate_percentage < 10 else ValidationSeverity.ERROR,
                passed=duplicate_percentage < 5,
                message=f"Duplicate rows: {duplicate_percentage:.2f}%",
                failed_count=duplicate_rows,
                total_count=len(df)
            ))
        else:
            self.validation_results.append(ValidationResult(
                rule_name="Data Uniqueness",
                field_name="all",
                severity=ValidationSeverity.INFO,
                passed=True,
                message="No duplicate rows found",
                total_count=len(df)
            ))
            
    def _is_valid_address(self, address: str) -> bool:
        """Check if address has valid format"""
        # Ethereum address
        if address.startswith('0x'):
            return len(address) == 42 and all(c in '0123456789abcdef' for c in address[2:])
        # Bitcoin address
        elif address.startswith('1') or address.startswith('3'):
            return 26 <= len(address) <= 35
        else:
            return False
            
    def _generate_quality_report(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Generate comprehensive quality report"""
        total_checks = len(self.validation_results)
        passed_checks = sum(1 for r in self.validation_results if r.passed)
        failed_checks = total_checks - passed_checks
        
        # Calculate quality score
        quality_score = passed_checks / total_checks if total_checks > 0 else 1.0
        
        # Count by severity
        severity_counts = {}
        for severity in ValidationSeverity:
            severity_counts[severity.value] = sum(1 for r in self.validation_results 
                                                if r.severity == severity)
        
        # Generate recommendations
        recommendations = []
        if failed_checks > 0:
            recommendations.append("Address validation failures to improve data quality")
        if any(r.severity == ValidationSeverity.CRITICAL for r in self.validation_results):
            recommendations.append("Critical issues must be resolved before processing")
            
        return {
            'quality_score': quality_score,
            'total_checks': total_checks,
            'passed_checks': passed_checks,
            'failed_checks': failed_checks,
            'severity_breakdown': severity_counts,
            'validation_results': [
                {
                    'rule_name': r.rule_name,
                    'field_name': r.field_name,
                    'severity': r.severity.value,
                    'passed': r.passed,
                    'message': r.message,
                    'failed_count': r.failed_count,
                    'total_count': r.total_count
                }
                for r in self.validation_results
            ],
            'recommendations': recommendations,
            'timestamp': datetime.utcnow().isoformat()
        }
        
    def get_validation_summary(self) -> Dict[str, Any]:
        """Get summary of validation results"""
        if not self.validation_results:
            return {}
            
        return {
            'total_checks': len(self.validation_results),
            'passed_checks': sum(1 for r in self.validation_results if r.passed),
            'failed_checks': sum(1 for r in self.validation_results if not r.passed),
            'critical_issues': sum(1 for r in self.validation_results 
                                 if r.severity == ValidationSeverity.CRITICAL and not r.passed),
            'quality_score': sum(1 for r in self.validation_results if r.passed) / len(self.validation_results)
        }
