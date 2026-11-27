use crate::report::{LayerId, Verdict};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Alerting {
    Strong,
    PotentiallyUnwanted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Alert {
    pub(crate) name: String,
    pub(crate) alerting: Alerting,
    pub(crate) layer: LayerId,
    pub(crate) object: LayerId,
}

#[derive(Debug, Default)]
pub(crate) struct Evidence {
    alerts: Vec<Alert>,
}

impl Evidence {
    pub(crate) fn record(&mut self, alert: Alert) {
        self.alerts.push(alert);
    }

    pub(crate) fn merge(&mut self, child: Self) {
        self.alerts.extend(child.alerts);
    }

    pub(crate) fn clear(&mut self) {
        self.alerts.clear();
    }

    pub(crate) fn verdict(&self) -> Verdict {
        if self.holds(Alerting::Strong) {
            Verdict::StrongIndicator
        } else if self.holds(Alerting::PotentiallyUnwanted) {
            Verdict::PotentiallyUnwanted
        } else {
            Verdict::NothingFound
        }
    }

    pub(crate) fn potentially_unwanted(&self) -> impl Iterator<Item = &Alert> {
        self.alerts
            .iter()
            .filter(|alert| alert.alerting == Alerting::PotentiallyUnwanted)
    }

    fn holds(&self, alerting: Alerting) -> bool {
        self.alerts.iter().any(|alert| alert.alerting == alerting)
    }
}
