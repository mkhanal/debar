use std::fmt;

use debar_image::{ICON_METRIC_POINTS, IconGroups, IconMetrics, IconPoint, IconSignature};

use crate::ignore_list::{IgnoreList, hex_value};

const COMMENT_MARK: u8 = b'#';
const SEPARATOR: u8 = b':';
const FIELD_COUNT: usize = 4;
const HASH_HEX_LENGTH: usize = 124;
const EDGE_LENGTHS: [u8; 3] = [16, 24, 32];
const LARGEST_COLOUR_AVERAGE: u16 = 4072;
const LARGEST_PRIMARY_SUM: u16 = 103;
const LARGEST_COLOUR_COUNT: u8 = 100;
const MOST_GROUPS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedIconLine {
    WrongFieldCount,
    WrongLength,
    NotHexadecimal,
    EdgeLength,
    Colour,
    Gray,
    Bright,
    Dark,
    Edge,
    NoEdge,
    Spread,
    TooManyGroups,
}

impl fmt::Display for MalformedIconLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::WrongFieldCount => "not four fields",
            Self::WrongLength => "the hash is not 124 hexadecimal digits",
            Self::NotHexadecimal => "the hash is not hexadecimal",
            Self::EdgeLength => "the icon edge length is not 16, 24 or 32",
            Self::Colour => "a colour metric is out of range",
            Self::Gray => "a gray metric is out of range",
            Self::Bright => "a bright metric is out of range",
            Self::Dark => "a dark metric is out of range",
            Self::Edge => "an edge metric is out of range",
            Self::NoEdge => "a no-edge metric is out of range",
            Self::Spread => "the colour spread is out of range",
            Self::TooManyGroups => "more than 256 icon groups",
        };
        formatter.write_str(text)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadIconLine {
    Comment,
    Ignored,
    Signature,
}

struct Nibbles {
    values: Vec<u8>,
    at: usize,
}

impl Nibbles {
    fn take(&mut self, count: usize) -> u16 {
        let value = self
            .values
            .get(self.at..self.at.saturating_add(count))
            .unwrap_or_default()
            .iter()
            .fold(0u16, |value, nibble| {
                value.wrapping_shl(4) | u16::from(*nibble)
            });
        self.at = self.at.saturating_add(count);
        value
    }

    fn byte(&mut self) -> u8 {
        u8::try_from(self.take(2)).unwrap_or(u8::MAX)
    }

    fn points(
        &mut self,
        average_nibbles: usize,
        largest_average: Option<u16>,
        limit: u8,
        malformed: MalformedIconLine,
    ) -> Result<[IconPoint; ICON_METRIC_POINTS], MalformedIconLine> {
        let mut points = [IconPoint::default(); ICON_METRIC_POINTS];
        for point in &mut points {
            let average = self.take(average_nibbles);
            if largest_average.is_some_and(|largest| average > largest) {
                return Err(malformed);
            }
            let x = self.byte();
            if x > limit {
                return Err(malformed);
            }
            let y = self.byte();
            if y > limit {
                return Err(malformed);
            }
            *point = IconPoint { average, x, y };
        }
        Ok(points)
    }
}

pub fn read_line(
    line_without_ending: &[u8],
    ignored: &IgnoreList,
    groups: &mut IconGroups,
) -> Result<ReadIconLine, MalformedIconLine> {
    if line_without_ending.first() == Some(&COMMENT_MARK) {
        return Ok(ReadIconLine::Comment);
    }
    let fields: Vec<&[u8]> = line_without_ending
        .split(|byte| *byte == SEPARATOR)
        .collect();
    let [name, first_group, second_group, hash] = fields.as_slice() else {
        return Err(MalformedIconLine::WrongFieldCount);
    };
    if fields.len() != FIELD_COUNT {
        return Err(MalformedIconLine::WrongFieldCount);
    }
    if hash.len() != HASH_HEX_LENGTH {
        return Err(MalformedIconLine::WrongLength);
    }
    if ignored.ignores(name, line_without_ending) {
        return Ok(ReadIconLine::Ignored);
    }
    let values = hash
        .iter()
        .map(|digit| hex_value(*digit))
        .collect::<Option<Vec<u8>>>()
        .ok_or(MalformedIconLine::NotHexadecimal)?;
    let mut nibbles = Nibbles { values, at: 0 };
    let edge_length = nibbles.byte();
    if !EDGE_LENGTHS.contains(&edge_length) {
        return Err(MalformedIconLine::EdgeLength);
    }
    let limit = edge_length.saturating_sub(edge_length / 8);
    let colour = nibbles.points(
        3,
        Some(LARGEST_COLOUR_AVERAGE),
        limit,
        MalformedIconLine::Colour,
    )?;
    let gray = nibbles.points(
        3,
        Some(LARGEST_COLOUR_AVERAGE),
        limit,
        MalformedIconLine::Gray,
    )?;
    let bright = nibbles.points(2, None, limit, MalformedIconLine::Bright)?;
    let dark = nibbles.points(2, None, limit, MalformedIconLine::Dark)?;
    let edge = nibbles.points(2, None, limit, MalformedIconLine::Edge)?;
    let no_edge = nibbles.points(2, None, limit, MalformedIconLine::NoEdge)?;
    let red_sum = nibbles.byte();
    let green_sum = nibbles.byte();
    let blue_sum = nibbles.byte();
    let colour_count = nibbles.byte();
    let primary_sum = u16::from(red_sum)
        .saturating_add(u16::from(green_sum))
        .saturating_add(u16::from(blue_sum));
    if primary_sum > LARGEST_PRIMARY_SUM || colour_count > LARGEST_COLOUR_COUNT {
        return Err(MalformedIconLine::Spread);
    }
    let first_group = group_index(&mut groups.first, first_group)?;
    let second_group = group_index(&mut groups.second, second_group)?;
    groups.signatures.push(IconSignature {
        name: String::from_utf8_lossy(name).into_owned(),
        first_group,
        second_group,
        metrics: IconMetrics {
            edge_length,
            colour,
            gray,
            bright,
            dark,
            edge,
            no_edge,
            red_sum,
            green_sum,
            blue_sum,
            colour_count,
        },
    });
    Ok(ReadIconLine::Signature)
}

fn group_index(names: &mut Vec<String>, name: &[u8]) -> Result<u16, MalformedIconLine> {
    let name = String::from_utf8_lossy(name);
    let index = if let Some(index) = names.iter().position(|known| *known == name) {
        index
    } else {
        names.push(name.into_owned());
        names.len().saturating_sub(1)
    };
    if names.len() > MOST_GROUPS {
        return Err(MalformedIconLine::TooManyGroups);
    }
    u16::try_from(index).map_err(|_| MalformedIconLine::TooManyGroups)
}
