# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Action packs imported for registration side effects."""

from . import cors, crawler, headers_cookies, jobs, workspace
from .. import catalog


__all__ = ["catalog", "cors", "crawler", "headers_cookies", "jobs", "workspace"]
