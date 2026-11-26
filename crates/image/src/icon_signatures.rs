use crate::record_codec::{
    FieldReader, RecordFields, RecordMalformed, RecordTooLarge, RecordWriter, Records,
};

pub const ICON_METRIC_POINTS: usize = 3;
const NAME_TABLES: u8 = 1;
const SIGNATURES: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IconPoint {
    pub average: u16,
    pub x: u8,
    pub y: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IconMetrics {
    pub edge_length: u8,
    pub colour: [IconPoint; ICON_METRIC_POINTS],
    pub gray: [IconPoint; ICON_METRIC_POINTS],
    pub bright: [IconPoint; ICON_METRIC_POINTS],
    pub dark: [IconPoint; ICON_METRIC_POINTS],
    pub edge: [IconPoint; ICON_METRIC_POINTS],
    pub no_edge: [IconPoint; ICON_METRIC_POINTS],
    pub red_sum: u8,
    pub green_sum: u8,
    pub blue_sum: u8,
    pub colour_count: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IconSignature {
    pub name: String,
    pub first_group: u16,
    pub second_group: u16,
    pub metrics: IconMetrics,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IconGroups {
    pub first: Vec<String>,
    pub second: Vec<String>,
    pub signatures: Vec<IconSignature>,
}

fn put_points(fields: &mut RecordFields, points: &[IconPoint; ICON_METRIC_POINTS]) {
    for point in points {
        fields.u16(point.average).byte(point.x).byte(point.y);
    }
}

fn points(
    fields: &mut FieldReader<'_>,
) -> Result<[IconPoint; ICON_METRIC_POINTS], RecordMalformed> {
    let mut points = [IconPoint::default(); ICON_METRIC_POINTS];
    for point in &mut points {
        *point = IconPoint {
            average: fields.u16()?,
            x: fields.byte()?,
            y: fields.byte()?,
        };
    }
    Ok(points)
}

pub fn build(groups: &IconGroups) -> Result<Vec<u8>, RecordTooLarge> {
    let mut writer = RecordWriter::default();
    let mut names = RecordFields::default();
    names.byte(NAME_TABLES);
    for table in [&groups.first, &groups.second] {
        names.count_of(table.len())?;
        for name in table {
            names.bytes(name.as_bytes())?;
        }
    }
    writer.record(&names)?;
    for signature in &groups.signatures {
        let metrics = &signature.metrics;
        let mut fields = RecordFields::default();
        fields
            .byte(SIGNATURES)
            .bytes(signature.name.as_bytes())?
            .u16(signature.first_group)
            .u16(signature.second_group)
            .byte(metrics.edge_length);
        for points in [
            &metrics.colour,
            &metrics.gray,
            &metrics.bright,
            &metrics.dark,
            &metrics.edge,
            &metrics.no_edge,
        ] {
            put_points(&mut fields, points);
        }
        fields
            .byte(metrics.red_sum)
            .byte(metrics.green_sum)
            .byte(metrics.blue_sum)
            .byte(metrics.colour_count);
        writer.record(&fields)?;
    }
    Ok(writer.finish())
}

pub fn read(bytes: &[u8]) -> Result<IconGroups, RecordMalformed> {
    let mut groups = IconGroups::default();
    let mut records = Records::read(bytes)?.each();
    let mut names = records.next().ok_or(RecordMalformed)??;
    if names.byte()? != NAME_TABLES {
        return Err(RecordMalformed);
    }
    for table in [&mut groups.first, &mut groups.second] {
        for _ in 0..names.count(4)? {
            table.push(names.text()?.to_owned());
        }
    }
    names.finish()?;
    for record in records {
        let mut fields = record?;
        if fields.byte()? != SIGNATURES {
            return Err(RecordMalformed);
        }
        let name = fields.text()?.to_owned();
        let first_group = fields.u16()?;
        let second_group = fields.u16()?;
        let edge_length = fields.byte()?;
        let metrics = IconMetrics {
            edge_length,
            colour: points(&mut fields)?,
            gray: points(&mut fields)?,
            bright: points(&mut fields)?,
            dark: points(&mut fields)?,
            edge: points(&mut fields)?,
            no_edge: points(&mut fields)?,
            red_sum: fields.byte()?,
            green_sum: fields.byte()?,
            blue_sum: fields.byte()?,
            colour_count: fields.byte()?,
        };
        fields.finish()?;
        groups.signatures.push(IconSignature {
            name,
            first_group,
            second_group,
            metrics,
        });
    }
    Ok(groups)
}
