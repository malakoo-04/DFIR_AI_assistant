from modules.llm.incident_analysis_agent import IncidentAnalysisAgent

agent = IncidentAnalysisAgent(
    model_name="qwen2.5:14b"
)

response = agent._call_model("Say only: connection successful.")

print(response)