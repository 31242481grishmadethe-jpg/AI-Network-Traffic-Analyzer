import json
import os
from typing import Dict, List, Optional
from config import LLM_PROVIDER, GROQ_API_KEY, GROQ_MODEL, OPENAI_API_KEY, OPENAI_MODEL
from ai.prompts import (
    SYSTEM_PROMPT, EXPLAIN_ALERT_PROMPT, SKEPTIC_PROMPT,
    CORRELATION_PROMPT, REPORT_PROMPT,
)
from ai.tools import (
    get_alert_details, search_traffic, get_host_history,
    get_related_events, get_dns_history, get_historical_baseline,
    get_investigation_evidence,
)

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "get_alert_details",
            "description": "Get detailed information about a specific alert by ID",
            "parameters": {
                "type": "object",
                "properties": {
                    "alert_id": {"type": "integer", "description": "The alert ID to look up"}
                },
                "required": ["alert_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_traffic",
            "description": "Search traffic flows by IP, protocol, or other filters",
            "parameters": {
                "type": "object",
                "properties": {
                    "source_ip": {"type": "string", "description": "Filter by source IP"},
                    "destination_ip": {"type": "string", "description": "Filter by destination IP"},
                    "protocol": {"type": "string", "description": "Filter by protocol (TCP, UDP, etc.)"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_host_history",
            "description": "Get historical traffic data for a specific host IP",
            "parameters": {
                "type": "object",
                "properties": {
                    "host_ip": {"type": "string", "description": "The host IP address"}
                },
                "required": ["host_ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_related_events",
            "description": "Find events related to a specific alert",
            "parameters": {
                "type": "object",
                "properties": {
                    "alert_id": {"type": "integer", "description": "The alert ID to find related events for"}
                },
                "required": ["alert_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_dns_history",
            "description": "Get DNS query history for a domain",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "The domain to look up"}
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_historical_baseline",
            "description": "Get the historical traffic baseline for a host",
            "parameters": {
                "type": "object",
                "properties": {
                    "host_ip": {"type": "string", "description": "The host IP address"}
                },
                "required": ["host_ip"],
            },
        },
    },
]

TOOL_MAP = {
    "get_alert_details": get_alert_details,
    "search_traffic": search_traffic,
    "get_host_history": get_host_history,
    "get_related_events": get_related_events,
    "get_dns_history": get_dns_history,
    "get_historical_baseline": get_historical_baseline,
}


class SecurityAnalyst:
    def __init__(self):
        self.provider = LLM_PROVIDER
        self.client = None
        self.model = None
        self.available = False

        if GROQ_API_KEY:
            try:
                from openai import OpenAI
                self.client = OpenAI(
                    api_key=GROQ_API_KEY,
                    base_url="https://api.groq.com/openai/v1",
                )
                self.model = GROQ_MODEL
                self.provider = "groq"
                self.available = True
            except Exception:
                pass

        if not self.available and OPENAI_API_KEY:
            try:
                from openai import OpenAI
                self.client = OpenAI(api_key=OPENAI_API_KEY)
                self.model = OPENAI_MODEL
                self.provider = "openai"
                self.available = True
            except Exception:
                pass

    def _call_llm(self, messages: list, tools: list = None) -> str:
        if not self.available:
            return (
                "AI features unavailable — configure GROQ_API_KEY in .env file.\n"
                "Example: GROQ_API_KEY=gsk_...\n"
                "Get a free key at: https://console.groq.com"
            )

        try:
            kwargs = {"model": self.model, "messages": messages, "temperature": 0.3}
            if tools and self.provider == "groq":
                kwargs["tools"] = tools
                kwargs["tool_choice"] = "auto"

            response = self.client.chat.completions.create(**kwargs)
            message = response.choices[0].message

            if hasattr(message, "tool_calls") and message.tool_calls:
                return self._handle_tool_calls(messages, message)

            return message.content or "No response generated."
        except Exception as e:
            return f"AI analysis error: {str(e)}"

    def _handle_tool_calls(self, messages: list, message) -> str:
        messages.append({"role": "assistant", "content": message.content, "tool_calls": [
            {"id": tc.id, "type": "function", "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
            for tc in message.tool_calls
        ]})

        for tool_call in message.tool_calls:
            func_name = tool_call.function.name
            try:
                args = json.loads(tool_call.function.arguments)
            except json.JSONDecodeError:
                args = {}

            tool_func = TOOL_MAP.get(func_name)
            if tool_func:
                result = tool_func(**args)
            else:
                result = {"error": f"Unknown tool: {func_name}"}

            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": json.dumps(result, default=str),
            })

        response = self.client.chat.completions.create(
            model=self.model, messages=messages, temperature=0.3,
        )
        return response.choices[0].message.content or "No response generated."

    def explain_alert(self, alert_data: dict) -> str:
        prompt = EXPLAIN_ALERT_PROMPT.format(
            alert_data=json.dumps(alert_data, indent=2, default=str)
        )
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        return self._call_llm(messages, tools=TOOL_DEFINITIONS)

    def chat(self, user_message: str, context: dict = None) -> str:
        system = SYSTEM_PROMPT
        if context:
            system += f"\n\nCurrent Context:\n{json.dumps(context, indent=2, default=str)}"

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user_message},
        ]
        return self._call_llm(messages, tools=TOOL_DEFINITIONS)

    def skeptic_analysis(self, hypothesis: str, alert_data: dict,
                         related_evidence: list) -> str:
        prompt = SKEPTIC_PROMPT.format(
            hypothesis=hypothesis,
            alert_data=json.dumps(alert_data, indent=2, default=str),
            related_evidence=json.dumps(related_evidence, indent=2, default=str),
        )
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        return self._call_llm(messages)

    def correlate_events(self, events: list) -> str:
        prompt = CORRELATION_PROMPT.format(
            events=json.dumps(events, indent=2, default=str)
        )
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        return self._call_llm(messages)

    def generate_report(self, case_data: dict, evidence: list, timeline: list) -> str:
        prompt = REPORT_PROMPT.format(
            case_data=json.dumps(case_data, indent=2, default=str),
            evidence=json.dumps(evidence, indent=2, default=str),
            timeline=json.dumps(timeline, indent=2, default=str),
        )
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        return self._call_llm(messages)
