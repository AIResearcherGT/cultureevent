import matplotlib.pyplot as plt
import pandas as pd
import datetime

# Define the project start date
start_date = datetime.datetime(2024, 6, 26)

# Define the schemes and their durations in days
schemes = {
    "Repertory Grant Scheme": 16,  # T + 2 weeks = 14 days + 2 days (assuming today is T)
    "Building Grant Scheme": 14,   # 2 weeks = 14 days
    "Senior Fellowship Scheme": 14, # 2 weeks = 14 days
    "Senior Young Artist Scheme": 14, # 2 weeks = 14 days
    "Junior Fellowship Scheme": 14  # 2 weeks = 14 days
}

# Create a DataFrame for the schemes and their start/end dates
data = []
for scheme, duration in schemes.items():
    end_date = start_date + datetime.timedelta(days=duration)
    data.append([scheme, start_date, end_date])

df = pd.DataFrame(data, columns=["Scheme", "Start Date", "End Date"])

# Plot the Gantt chart
fig, ax = plt.subplots(figsize=(10, 6))
for i, row in df.iterrows():
    ax.barh(row["Scheme"], (row["End Date"] - row["Start Date"]).days, left=row["Start Date"], color='skyblue')
    ax.text(row["Start Date"], i, row["Start Date"].strftime('%Y-%m-%d'), va='center', ha='right', color='black', fontsize=10)
    ax.text(row["End Date"], i, row["End Date"].strftime('%Y-%m-%d'), va='center', ha='left', color='black', fontsize=10)

# Format the chart
ax.set_xlabel('Date')
ax.set_ylabel('Schemes')
ax.set_title('Project Timeline')
ax.xaxis_date()
plt.xticks(rotation=45)
plt.grid(axis='x')

plt.show()
