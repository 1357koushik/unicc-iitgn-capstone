"""
Network Security AI Sensor - UNICC evaluation Task 5.0 (Team 4).

Looks at records of network connections and flags the ones that look like attacks,
using three machine-learning models that check each other:

  * Isolation Forest  - learned only what NORMAL traffic looks like; flags outliers
  * One-Class SVM     - a second, differently built "normal-only" model
  * Random Forest     - learned from labelled examples of known attacks

A connection is flagged as an attack if the Random Forest recognises a known attack,
OR if BOTH normal-only models agree that it is abnormal. The second part is what
catches new kinds of attack that the Random Forest never saw during training.

Commands (run them in the project folder, with the .venv switched on):
    python -m network_sensor.download_data    # get the public NSL-KDD dataset
    python -m network_sensor.train            # train the three models
    python -m network_sensor.evaluate         # precision / recall report on the test set
"""
